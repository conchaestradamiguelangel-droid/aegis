"""
AEGIS — Capa de Persistencia (Hueco #7)
Checkpoint atómico del estado completo. Si el proceso muere, AEGIS no empieza de cero.
"""

import asyncio
import gzip
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

logger = logging.getLogger("aegis.persistence")

DEFAULT_STATE_DIR             = "state"
DEFAULT_CHECKPOINT_INTERVAL_S = 60
DEFAULT_MAX_HISTORY           = 50
DEFAULT_LOG_MAX_BYTES         = 10 * 1024 * 1024  # 10MB


class AegisEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, "to_dict"):
            return obj.to_dict()
        if hasattr(obj, "__dict__"):
            return {k: v for k, v in obj.__dict__.items()
                    if not k.startswith("_") and not callable(v)}
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        if obj is None:
            return None
        return str(obj)


class CheckpointManager:
    """Gestiona checkpoints atómicos del sistema AEGIS a disco."""

    def __init__(
        self,
        state_dir:     str = DEFAULT_STATE_DIR,
        max_history:   int = DEFAULT_MAX_HISTORY,
        log_max_bytes: int = DEFAULT_LOG_MAX_BYTES,
    ):
        self._state_dir     = Path(state_dir)
        self._max_history   = max_history
        self._log_max_bytes = log_max_bytes

        self._checkpoint_dir = self._state_dir / "checkpoints"
        self._history_dir    = self._state_dir / "history"
        self._incidents_dir  = self._state_dir / "incidents"
        self._logs_dir       = self._state_dir / "logs"

        self._ensure_dirs()
        self._checkpoint_count      = 0
        self._last_checkpoint_bytes = 0

        logger.info(f"[PERSIST] CheckpointManager activo — dir={self._state_dir}")

    def _ensure_dirs(self):
        for d in [self._state_dir, self._checkpoint_dir,
                  self._history_dir, self._incidents_dir, self._logs_dir]:
            d.mkdir(parents=True, exist_ok=True)

    @property
    def incidents_dir(self) -> Path:
        return self._incidents_dir

    @property
    def logs_dir(self) -> Path:
        return self._logs_dir

    def save_checkpoint(self, data: Any) -> dict:
        """Escribe checkpoint completo de forma atómica (tmp → rename)."""
        t0      = time.monotonic()
        now     = datetime.now(timezone.utc)
        ckpt_id = f"ckpt_{self._checkpoint_count:04d}"

        payload    = {"checkpoint_id": ckpt_id, "timestamp": now.isoformat(),
                      "aegis_version": "1.0", "data": self._to_serializable(data)}
        serialized = json.dumps(payload, cls=AegisEncoder, ensure_ascii=False)
        bytes_len  = len(serialized.encode("utf-8"))

        main_path = self._checkpoint_dir / "latest.json"
        tmp_main  = main_path.with_suffix(".json.tmp")
        try:
            tmp_main.write_text(serialized, encoding="utf-8")
            tmp_main.rename(main_path)
        except Exception as e:
            logger.error(f"[PERSIST] Error escribiendo checkpoint: {e}")
            tmp_main.unlink(missing_ok=True)
            return {"error": str(e)}

        hist_path = self._history_dir / f"checkpoint_{now.strftime('%Y%m%d_%H%M%S')}.json.gz"
        try:
            with gzip.open(hist_path, "wt", encoding="utf-8") as f:
                f.write(serialized)
        except Exception as e:
            logger.warning(f"[PERSIST] Error escribiendo histórico: {e}")

        self._rotate_history()
        self._checkpoint_count      += 1
        self._last_checkpoint_bytes  = bytes_len
        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug(f"[PERSIST] Checkpoint — id={ckpt_id} bytes={bytes_len} elapsed={elapsed_ms:.1f}ms")
        return {"checkpoint_id": ckpt_id, "timestamp": now.isoformat(),
                "bytes": bytes_len, "elapsed_ms": round(elapsed_ms, 1)}

    def load_latest_checkpoint(self) -> Optional[dict]:
        """Carga el último checkpoint. Retorna None si no existe."""
        main_path = self._checkpoint_dir / "latest.json"
        if not main_path.exists():
            logger.info("[PERSIST] Sin checkpoint previo — sistema limpio")
            return None
        try:
            data = json.loads(main_path.read_text(encoding="utf-8"))
            logger.info(f"[PERSIST] Checkpoint cargado — id={data.get('checkpoint_id','?')} ts={data.get('timestamp','?')}")
            return data
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"[PERSIST] Error cargando checkpoint: {e}")
            return None

    def save_incident(self, incident_id: str, profile_data: dict):
        """Escribe perfil de incidente a JSONL con fsync."""
        path = self._incidents_dir / f"incident_{incident_id}.jsonl"
        try:
            with open(path, "a", encoding="utf-8") as f:
                line = json.dumps(
                    {"ts": datetime.now(timezone.utc).isoformat(),
                     "incident": incident_id,
                     "data": self._to_serializable(profile_data)},
                    cls=AegisEncoder, ensure_ascii=False,
                )
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            logger.error(f"[PERSIST] Error guardando incidente {incident_id}: {e}")

    def append_detection(self, detection: dict):
        """Streaming de detecciones a JSONL rotante."""
        self._append_rotating_log("detection_log",
            {"ts": datetime.now(timezone.utc).isoformat(),
             "detection": self._to_serializable(detection)})

    def append_sync_event(self, event: dict):
        """Registra eventos de sincronización entre gemelos."""
        self._append_rotating_log("sync_log",
            {"ts": datetime.now(timezone.utc).isoformat(),
             "event": self._to_serializable(event)})

    def _append_rotating_log(self, basename: str, entry: dict):
        log_path   = self._logs_dir / f"{basename}.jsonl"
        try:
            line       = json.dumps(entry, cls=AegisEncoder, ensure_ascii=False)
            line_bytes = len(line.encode("utf-8")) + 1
            if log_path.exists() and log_path.stat().st_size + line_bytes > self._log_max_bytes:
                self._rotate_log_file(log_path)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            logger.warning(f"[PERSIST] Error escribiendo log {basename}: {e}")

    def _rotate_log_file(self, path: Path):
        try:
            data    = path.read_bytes()
            rotated = path.with_name(f"{path.stem}_1.jsonl.gz")
            with gzip.open(rotated, "wb") as f:
                f.write(data)
            path.write_text("", encoding="utf-8")
            logger.info(f"[PERSIST] Log rotado: {path.name} → {rotated.name}")
        except OSError as e:
            logger.warning(f"[PERSIST] Error rotando log: {e}")

    def _rotate_history(self):
        history_files = sorted(self._history_dir.glob("checkpoint_*.json.gz"))
        if len(history_files) <= self._max_history:
            return
        for f in history_files[:-self._max_history]:
            try:
                f.unlink()
            except OSError:
                pass

    @staticmethod
    def _to_serializable(obj: Any) -> Any:
        if obj is None:
            return None
        if isinstance(obj, (str, int, float, bool)):
            return obj
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, dict):
            return {k: CheckpointManager._to_serializable(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [CheckpointManager._to_serializable(item) for item in obj]
        if hasattr(obj, "to_dict"):
            return CheckpointManager._to_serializable(obj.to_dict())
        if hasattr(obj, "__dict__"):
            return CheckpointManager._to_serializable(obj.__dict__)
        return str(obj)

    def status(self) -> dict:
        return {
            "state_dir":             str(self._state_dir),
            "checkpoints_created":   self._checkpoint_count,
            "last_checkpoint_bytes": self._last_checkpoint_bytes,
            "history_files":         len(list(self._history_dir.glob("checkpoint_*.json.gz"))),
            "incident_files":        len(list(self._incidents_dir.glob("*.jsonl"))),
            "max_history":           self._max_history,
        }


class AutoCheckpointer:
    """Ejecuta checkpoint automático cada N segundos como tarea asyncio."""

    def __init__(
        self,
        manager:              CheckpointManager,
        snapshot_fn,
        interval_s:           int = DEFAULT_CHECKPOINT_INTERVAL_S,
        post_checkpoint_fn         = None,
    ):
        self._manager            = manager
        self._snapshot_fn        = snapshot_fn
        self._interval_s         = interval_s
        self._post_checkpoint_fn = post_checkpoint_fn
        self._task: Optional[asyncio.Task] = None
        self._running            = False
        self._count              = 0

    async def start(self):
        if self._running:
            return
        self._running = True
        self._task    = asyncio.create_task(self._loop(), name="aegis.persistence.checkpoint")
        logger.info(f"[PERSIST] AutoCheckpointer iniciado — intervalo={self._interval_s}s")

    async def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[PERSIST] AutoCheckpointer detenido")

    async def _loop(self):
        await asyncio.sleep(self._interval_s)  # delay inicial — no checkpoint al arrancar
        while self._running:
            try:
                snapshot = await self._snapshot_fn()
                result   = self._manager.save_checkpoint(snapshot)
                if self._post_checkpoint_fn and "error" not in result:
                    try:
                        self._post_checkpoint_fn()
                    except Exception as _pce:
                        logger.warning(f"[PERSIST] Error en post_checkpoint: {_pce}")
                self._count += 1
                await asyncio.sleep(self._interval_s)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[PERSIST] Error en checkpoint automático: {e}")
                await asyncio.sleep(self._interval_s)

    def status(self) -> dict:
        return {"running": self._running, "interval_s": self._interval_s,
                "checkpoints_done": self._count}
