"""AEGIS — Write-Ahead Log para mutaciones críticas de blocklist."""

import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("aegis.wal")


class WALManager:
    """
    WAL file-per-op: un fichero JSON por operacion en vuelo.

    Antes de cada mutacion:
        wal_path = wal.write("block_ip", {"ip": x, "ttl_s": y})
        blocklist.block(x, ttl_s=y)
        wal.commit(wal_path)

    En startup (antes de aceptar trafico):
        for path, entry in wal.recover():
            replay(entry)
            wal.commit(path)
    """

    def __init__(self, wal_dir):
        self._wal_dir = Path(wal_dir)
        self._wal_dir.mkdir(parents=True, exist_ok=True)

    def write(self, op, params):
        """Escribe entrada WAL a disco con fsync antes de la mutacion."""
        entry_id = secrets.token_hex(8)
        payload = {
            "id":     entry_id,
            "ts":     datetime.now(timezone.utc).isoformat(),
            "op":     op,
            "params": params,
        }
        path = self._wal_dir / f"op_{entry_id}.json"
        tmp  = path.with_suffix(".json.tmp")
        try:
            serialized = json.dumps(payload, ensure_ascii=False)
            tmp.write_text(serialized, encoding="utf-8")
            with open(tmp, "rb") as f:
                os.fsync(f.fileno())
            tmp.rename(path)
            logger.debug(f"[WAL] write op={op} id={entry_id}")
        except OSError as e:
            logger.error(f"[WAL] Error escribiendo op={op}: {e}")
            tmp.unlink(missing_ok=True)
            raise
        return path

    def commit(self, wal_path):
        """Elimina la entrada WAL tras completar la mutacion."""
        try:
            wal_path.unlink(missing_ok=True)
        except OSError as e:
            logger.warning(f"[WAL] Error en commit {wal_path.name}: {e}")

    def recover(self):
        """
        Retorna operaciones pendientes ordenadas por timestamp.
        Elimina automaticamente entradas corruptas.
        Retorna lista de (Path, dict).
        """
        pending = []
        for p in sorted(self._wal_dir.glob("op_*.json")):
            try:
                entry = json.loads(p.read_text(encoding="utf-8"))
                pending.append((p, entry))
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"[WAL] Entrada corrupta {p.name}: {e} — eliminada")
                p.unlink(missing_ok=True)
        if pending:
            logger.warning(f"[WAL] Recovery: {len(pending)} operaciones pendientes")
        return pending

    def flush(self):
        """Elimina todas las entradas WAL (llamar tras checkpoint exitoso)."""
        for p in self._wal_dir.glob("op_*.json"):
            try:
                p.unlink()
            except OSError:
                pass
        logger.debug("[WAL] Flush completado tras checkpoint")

    def pending_count(self):
        return len(list(self._wal_dir.glob("op_*.json")))
