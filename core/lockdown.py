"""
AEGIS — Capa 4: Cierre Atómico
================================
Objetivo: contención completa del perímetro en < 3 segundos.
Límite máximo absoluto: < 100ms por operación individual.
Todas las capas simultáneas — nunca secuencial.

FILOSOFÍA:
    Cuando se activa el cierre, no hay negociación.
    Todo ocurre a la vez — asyncio.gather() en cada operación.
    El intruso no tiene tiempo de reaccionar entre pasos.

ACCIONES DE CIERRE (simultáneas):
    1. Notificar Capa 1 (twin)     → salto atómico de cadena
    2. Sellar sesiones activas      → invalidar tokens y contextos
    3. Rotar credenciales críticas  → nuevas claves, tokens inválidos
    4. Cerrar superficies           → puertos señuelo, endpoints expuestos
    5. Congelar estado forense      → snapshot para Capa 7

COORDINACIÓN:
    → Capa 1 (twin): trigger_jump()
    → Capa 3 (detector): registra el evento de lockdown
    → Capa 7 (forensics): recibe snapshot del estado en el momento del cierre

REGLAS INVARIABLES:
    - asyncio puro — cero threading, cero blocking
    - Todas las operaciones en asyncio.gather() — nunca await secuencial
    - < 100ms por operación individual
    - < 3s cierre completo
    - Idempotente — activar dos veces no rompe nada
"""

import asyncio
import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("aegis.lockdown")


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class LockdownTrigger(str, Enum):
    DETECTION   = "DETECTION"    # disparado por Capa 3
    MANUAL      = "MANUAL"       # activación manual por operador
    SCHEDULED   = "SCHEDULED"    # rotación programada
    CASCADE     = "CASCADE"      # cascada desde otro lockdown


class LockdownStatus(str, Enum):
    IDLE        = "IDLE"         # en espera — sin amenaza activa
    ACTIVE      = "ACTIVE"       # cierre en progreso
    SEALED      = "SEALED"       # cierre completado — perímetro cerrado
    RECOVERING  = "RECOVERING"   # restaurando operación normal


# ─────────────────────────────────────────────
# RESULTADO DE CIERRE
# ─────────────────────────────────────────────

@dataclass
class LockdownResult:
    """Resultado completo de una operación de cierre."""
    lockdown_id:      str
    trigger:          LockdownTrigger
    triggered_at:     datetime
    completed_at:     Optional[datetime]
    total_ms:         float
    success:          bool

    # Resultados por operación
    twin_jump_ms:     float = 0.0
    sessions_sealed_ms: float = 0.0
    credentials_rotated_ms: float = 0.0
    surfaces_closed_ms: float = 0.0
    forensic_snapshot_ms: float = 0.0

    sessions_invalidated: int = 0
    credentials_rotated:  int = 0
    surfaces_closed:      int = 0

    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["trigger"]       = self.trigger.value
        d["triggered_at"]  = self.triggered_at.isoformat()
        d["completed_at"]  = self.completed_at.isoformat() if self.completed_at else None
        return d

    def within_limits(self) -> bool:
        """Verifica que todas las operaciones cumplieron el límite de 100ms."""
        ops = [
            self.twin_jump_ms,
            self.sessions_sealed_ms,
            self.credentials_rotated_ms,
            self.surfaces_closed_ms,
            self.forensic_snapshot_ms,
        ]
        return all(ms < 100 for ms in ops if ms > 0)


# ─────────────────────────────────────────────
# OPERACIÓN 1 — NOTIFICAR CAPA 1 (TWIN JUMP)
# ─────────────────────────────────────────────

class TwinJumpOperation:
    """
    Coordina con Capa 1 para disparar el salto atómico de cadena.
    El twin ya tiene su propio motor — aquí solo lo activamos.
    """

    def __init__(self):
        self._jump_callback: Optional[Callable] = None

    def set_jump_callback(self, cb: Callable):
        self._jump_callback = cb

    async def execute(self, lockdown_id: str) -> float:
        """Dispara salto en Capa 1. Retorna ms empleados."""
        t0 = time.monotonic()
        if self._jump_callback:
            try:
                if asyncio.iscoroutinefunction(self._jump_callback):
                    await self._jump_callback(lockdown_id)
                else:
                    self._jump_callback(lockdown_id)
                logger.info(f"[LOCKDOWN.TWIN] Salto disparado — lockdown={lockdown_id}")
            except Exception as e:
                logger.error(f"[LOCKDOWN.TWIN] Error disparando salto: {e}")
        else:
            logger.warning("[LOCKDOWN.TWIN] Sin callback de twin — salto omitido")
        return (time.monotonic() - t0) * 1000


# ─────────────────────────────────────────────
# OPERACIÓN 2 — SELLAR SESIONES
# ─────────────────────────────────────────────

class SessionSealOperation:
    """
    Invalida todas las sesiones activas en el momento del cierre.
    Los tokens existentes dejan de ser válidos inmediatamente.
    """

    def __init__(self):
        self._active_sessions: dict = {}     # session_id → metadata
        self._sealed_sessions: dict = {}     # session_id → sealed_at

    def register_session(self, session_id: str, metadata: dict):
        """Registra una sesión activa para monitorización."""
        self._active_sessions[session_id] = metadata

    async def execute(self, lockdown_id: str) -> tuple:
        """
        Sella todas las sesiones activas simultáneamente.
        Retorna (ms_empleados, num_sesiones_selladas).
        """
        t0       = time.monotonic()
        count    = len(self._active_sessions)
        sealed_at = datetime.now(timezone.utc).isoformat()

        # Sellar todas a la vez
        async def seal_one(sid: str):
            self._sealed_sessions[sid] = {
                "sealed_at":   sealed_at,
                "lockdown_id": lockdown_id,
                "reason":      "LOCKDOWN",
            }

        if self._active_sessions:
            await asyncio.gather(*[seal_one(sid) for sid in self._active_sessions])

        self._active_sessions.clear()

        ms = (time.monotonic() - t0) * 1000
        logger.info(f"[LOCKDOWN.SESSIONS] {count} sesiones selladas en {ms:.2f}ms")
        return ms, count

    def is_sealed(self, session_id: str) -> bool:
        return session_id in self._sealed_sessions

    def active_count(self) -> int:
        return len(self._active_sessions)


# ─────────────────────────────────────────────
# OPERACIÓN 3 — ROTAR CREDENCIALES
# ─────────────────────────────────────────────

class CredentialRotationOperation:
    """
    Rota credenciales críticas en el momento del cierre.
    Las credenciales anteriores quedan invalidadas.
    Genera nuevas con entropía criptográfica — nunca predecibles.
    """

    def __init__(self):
        self._credentials: dict = {}   # name → current_hash
        self._rotations:   list = []   # historial de rotaciones

    def register_credential(self, name: str, value_hash: str):
        """Registra una credencial para rotación automática en lockdown."""
        self._credentials[name] = value_hash

    async def execute(self, lockdown_id: str) -> tuple:
        """
        Rota todas las credenciales registradas simultáneamente.
        Retorna (ms_empleados, num_rotadas).
        """
        t0    = time.monotonic()
        count = len(self._credentials)

        async def rotate_one(name: str):
            new_value = secrets.token_bytes(32)
            new_hash  = hashlib.sha3_256(new_value).hexdigest()
            old_hash  = self._credentials[name]
            self._credentials[name] = new_hash
            self._rotations.append({
                "name":        name,
                "old_hash":    old_hash[:8] + "...",
                "new_hash":    new_hash[:8] + "...",
                "lockdown_id": lockdown_id,
                "rotated_at":  datetime.now(timezone.utc).isoformat(),
            })
            logger.debug(f"[LOCKDOWN.CREDS] Rotada: {name}")

        if self._credentials:
            await asyncio.gather(*[rotate_one(name) for name in list(self._credentials)])

        ms = (time.monotonic() - t0) * 1000
        logger.info(f"[LOCKDOWN.CREDS] {count} credenciales rotadas en {ms:.2f}ms")
        return ms, count

    def get_rotation_log(self) -> list:
        return list(self._rotations)


# ─────────────────────────────────────────────
# OPERACIÓN 4 — CERRAR SUPERFICIES
# ─────────────────────────────────────────────

class SurfaceCloseOperation:
    """
    Cierra superficies de ataque registradas.
    Puertos señuelo, endpoints expuestos, canales de comunicación.
    Coordina con Capa 0.5 (shield) y Capa 5 (AMTD) cuando estén activas.
    """

    def __init__(self):
        self._surfaces:      dict  = {}    # name → {"type": ..., "close_fn": ...}
        self._closed:        dict  = {}    # name → closed_at
        self._close_callbacks: list = []   # callbacks externos (shield, amtd)

    def register_surface(self, name: str, surface_type: str, close_fn: Optional[Callable] = None):
        """Registra una superficie de ataque para cierre automático en lockdown."""
        self._surfaces[name] = {"type": surface_type, "close_fn": close_fn}

    def register_close_callback(self, cb: Callable):
        """Callback externo que se llama al cerrar superficies (Capa 0.5, Capa 5)."""
        self._close_callbacks.append(cb)

    async def execute(self, lockdown_id: str) -> tuple:
        """
        Cierra todas las superficies simultáneamente.
        Retorna (ms_empleados, num_cerradas).
        """
        t0    = time.monotonic()
        count = len(self._surfaces)

        async def close_one(name: str, config: dict):
            closed_at = datetime.now(timezone.utc).isoformat()
            # Ejecutar función de cierre específica si existe
            fn = config.get("close_fn")
            if fn:
                try:
                    if asyncio.iscoroutinefunction(fn):
                        await fn()
                    else:
                        fn()
                except Exception as e:
                    logger.warning(f"[LOCKDOWN.SURFACE] Error cerrando {name}: {e}")
            self._closed[name] = {
                "closed_at":   closed_at,
                "type":        config["type"],
                "lockdown_id": lockdown_id,
            }
            logger.debug(f"[LOCKDOWN.SURFACE] Cerrada: {name} ({config['type']})")

        tasks = [close_one(n, c) for n, c in self._surfaces.items()]

        # Callbacks externos también simultáneos
        async def call_cb(cb):
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(lockdown_id)
                else:
                    cb(lockdown_id)
            except Exception as e:
                logger.warning(f"[LOCKDOWN.SURFACE] Error en callback: {e}")

        tasks += [call_cb(cb) for cb in self._close_callbacks]

        if tasks:
            await asyncio.gather(*tasks)

        ms = (time.monotonic() - t0) * 1000
        logger.info(f"[LOCKDOWN.SURFACE] {count} superficies cerradas en {ms:.2f}ms")
        return ms, count

    def is_closed(self, name: str) -> bool:
        return name in self._closed


# ─────────────────────────────────────────────
# OPERACIÓN 5 — SNAPSHOT FORENSE
# ─────────────────────────────────────────────

class ForensicSnapshotOperation:
    """
    Congela el estado del sistema en el momento exacto del cierre.
    Snapshot completo para Capa 7 (análisis forense).
    Debe ejecutarse simultáneamente con el resto — no después.
    """

    def __init__(self):
        self._snapshots:        list = []
        self._forensic_callbacks: list = []

    def register_forensic_callback(self, cb: Callable):
        """Capa 7 — recibe el snapshot en tiempo real."""
        self._forensic_callbacks.append(cb)

    async def execute(self, lockdown_id: str, context: dict) -> float:
        """
        Captura snapshot y lo envía a Capa 7.
        context: estado del sistema en el momento del cierre.
        Retorna ms_empleados.
        """
        t0 = time.monotonic()

        snapshot = {
            "lockdown_id":  lockdown_id,
            "captured_at":  datetime.now(timezone.utc).isoformat(),
            "context":      context,
            "snapshot_id":  secrets.token_hex(8).upper(),
        }
        self._snapshots.append(snapshot)

        # Enviar a todos los callbacks de Capa 7 simultáneamente
        async def send_one(cb):
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(snapshot)
                else:
                    cb(snapshot)
            except Exception as e:
                logger.warning(f"[LOCKDOWN.FORENSIC] Error en callback: {e}")

        if self._forensic_callbacks:
            await asyncio.gather(*[send_one(cb) for cb in self._forensic_callbacks])

        ms = (time.monotonic() - t0) * 1000
        logger.info(f"[LOCKDOWN.FORENSIC] Snapshot capturado en {ms:.2f}ms")
        return ms

    def get_snapshots(self) -> list:
        return list(self._snapshots)


# ─────────────────────────────────────────────
# FACHADA PRINCIPAL — AegisLockdown
# ─────────────────────────────────────────────

class AegisLockdown:
    """
    Fachada de Capa 4 — Cierre Atómico.

    GARANTÍA: todas las operaciones se ejecutan en asyncio.gather()
    nunca de forma secuencial. El tiempo total es el de la operación
    más lenta, no la suma de todas.

    Uso:
        lockdown = AegisLockdown()

        # Conectar con otras capas
        lockdown.set_twin_jump_callback(twin_chain.trigger_jump)
        lockdown.register_forensic_callback(forensics.ingest)

        # Registrar recursos a proteger
        lockdown.register_session("sess_abc123", {"user": "admin"})
        lockdown.register_credential("db_password", hash_value)
        lockdown.register_surface("decoy_8080", "http_decoy", close_fn)

        # Activar (desde Capa 3 o manualmente)
        result = await lockdown.execute(LockdownTrigger.DETECTION, context={})
    """

    def __init__(self):
        self._twin_op       = TwinJumpOperation()
        self._session_op    = SessionSealOperation()
        self._credential_op = CredentialRotationOperation()
        self._surface_op    = SurfaceCloseOperation()
        self._forensic_op   = ForensicSnapshotOperation()

        self._status        = LockdownStatus.IDLE
        self._results:      list = []
        self._lock          = asyncio.Lock()   # un solo lockdown a la vez

        logger.info("[AEGIS.Lockdown] Capa 4 inicializada — cierre atómico listo")

    # ── Configuración — conectores con otras capas ────────────────────────────

    def set_twin_jump_callback(self, cb: Callable):
        """Capa 1 — salto atómico de cadena."""
        self._twin_op.set_jump_callback(cb)

    def register_forensic_callback(self, cb: Callable):
        """Capa 7 — recibe snapshot en tiempo real."""
        self._forensic_op.register_forensic_callback(cb)

    def register_surface_close_callback(self, cb: Callable):
        """Capa 0.5 / Capa 5 — cierre de superficies externas."""
        self._surface_op.register_close_callback(cb)

    # ── Registro de recursos ─────────────────────────────────────────────────

    def register_session(self, session_id: str, metadata: dict):
        """Registra sesión para sellado automático en lockdown."""
        self._session_op.register_session(session_id, metadata)

    def register_credential(self, name: str, value_hash: str):
        """Registra credencial para rotación automática en lockdown."""
        self._credential_op.register_credential(name, value_hash)

    def register_surface(
        self, name: str, surface_type: str,
        close_fn: Optional[Callable] = None
    ):
        """Registra superficie de ataque para cierre en lockdown."""
        self._surface_op.register_surface(name, surface_type, close_fn)

    # ── Ejecución del cierre ─────────────────────────────────────────────────

    async def execute(
        self,
        trigger:  LockdownTrigger = LockdownTrigger.DETECTION,
        context:  dict = None,
        notes:    str  = ""
    ) -> LockdownResult:
        """
        Ejecuta el cierre atómico completo.
        Todas las operaciones simultáneas — nunca secuenciales.
        Idempotente — si ya está en SEALED, retorna el último resultado.
        El check de idempotencia está dentro del lock para garantizar
        que llamadas concurrentes no entren múltiples veces.
        """
        async with self._lock:
            # Idempotencia dentro del lock — concurrencia segura
            if self._status == LockdownStatus.SEALED:
                logger.warning("[LOCKDOWN] Ya sellado — ignorando solicitud duplicada")
                return self._results[-1] if self._results else None
            lockdown_id  = secrets.token_hex(6).upper()
            triggered_at = datetime.now(timezone.utc)
            t_total      = time.monotonic()
            context      = context or {}

            logger.warning(
                f"[LOCKDOWN] ⚡ CIERRE ATÓMICO INICIADO — "
                f"id={lockdown_id} trigger={trigger.value}"
            )

            self._status = LockdownStatus.ACTIVE

            # ── TODAS LAS OPERACIONES SIMULTÁNEAS ────────────────────────────
            # asyncio.gather() — el tiempo total = max(t_op1, t_op2, ..., t_opN)
            # No la suma — todas corren en paralelo.

            gather_results = await asyncio.gather(
                self._twin_op.execute(lockdown_id),
                self._session_op.execute(lockdown_id),
                self._credential_op.execute(lockdown_id),
                self._surface_op.execute(lockdown_id),
                self._forensic_op.execute(lockdown_id, context),
                return_exceptions=True,
            )

            op_errors = [r for r in gather_results if isinstance(r, Exception)]
            if op_errors:
                for err in op_errors:
                    logger.error(f"[LOCKDOWN] Operación fallida: {err}")

            def _safe(val, default):
                return val if not isinstance(val, Exception) else default

            twin_ms                        = _safe(gather_results[0], 0.0)
            sessions_ms, sessions_count    = _safe(gather_results[1], (0.0, 0))
            creds_ms, creds_count          = _safe(gather_results[2], (0.0, 0))
            surfaces_ms, surfaces_count    = _safe(gather_results[3], (0.0, 0))
            forensic_ms                    = _safe(gather_results[4], 0.0)

            total_ms     = (time.monotonic() - t_total) * 1000
            self._status = LockdownStatus.SEALED

            result = LockdownResult(
                lockdown_id              = lockdown_id,
                trigger                  = trigger,
                triggered_at             = triggered_at,
                completed_at             = datetime.now(timezone.utc),
                total_ms                 = total_ms,
                success                  = len(op_errors) == 0,
                twin_jump_ms             = twin_ms,
                sessions_sealed_ms       = sessions_ms,
                credentials_rotated_ms   = creds_ms,
                surfaces_closed_ms       = surfaces_ms,
                forensic_snapshot_ms     = forensic_ms,
                sessions_invalidated     = sessions_count,
                credentials_rotated      = creds_count,
                surfaces_closed          = surfaces_count,
                notes                    = notes,
            )
            self._results.append(result)

            within = result.within_limits()
            logger.warning(
                f"[LOCKDOWN] ✓ CIERRE COMPLETADO — "
                f"id={lockdown_id} "
                f"total={total_ms:.2f}ms "
                f"límites={'OK' if within else 'SUPERADOS'} | "
                f"sesiones={sessions_count} "
                f"creds={creds_count} "
                f"superficies={surfaces_count}"
            )
            if not within:
                logger.error(
                    f"[LOCKDOWN] ⚠ OPERACIONES FUERA DE LÍMITE — "
                    f"twin={twin_ms:.1f}ms "
                    f"sessions={sessions_ms:.1f}ms "
                    f"creds={creds_ms:.1f}ms "
                    f"surfaces={surfaces_ms:.1f}ms "
                    f"forensic={forensic_ms:.1f}ms"
                )

            return result

    async def reset(self):
        """
        Restaura el lockdown a IDLE para permitir nueva activación.
        Solo para uso en tests o tras recuperación verificada.
        """
        async with self._lock:
            self._status = LockdownStatus.IDLE
            logger.info("[LOCKDOWN] Reset a IDLE — listo para nueva activación")

    # ── Consultas ─────────────────────────────────────────────────────────────

    @property
    def status(self) -> LockdownStatus:
        return self._status

    def is_sealed(self) -> bool:
        return self._status == LockdownStatus.SEALED

    def get_result_log(self) -> list:
        return [r.to_dict() for r in self._results]

    def last_result(self) -> Optional[LockdownResult]:
        return self._results[-1] if self._results else None

    def aegis_status(self) -> dict:
        return {
            "status":        self._status.value,
            "total_lockdowns": len(self._results),
            "active_sessions": self._session_op.active_count(),
            "surfaces_registered": len(self._surface_op._surfaces),
            "credentials_registered": len(self._credential_op._credentials),
        }
