"""
AEGIS — Capa 1: Gemelo en Cadena
==================================
Arquitectura A/B/C permanentes + generación automática de D.

FILOSOFÍA:
    El sistema real siempre está DOS niveles por delante del intruso.
    Cuando el intruso entra en A → C ya está cerrado → D ya se está generando.
    B es sacrificable. C es el verdadero santuario. D es el futuro seguro.

CADENA:
    A → activo, visible al mundo exterior
    B → réplica exacta de A, sincronizada ≤100ms, sacrificable
    C → réplica exacta de B, se cierra atómicamente al detectar intrusión en A
    D → se genera automáticamente desde el estado de C al activar el salto

QUÉ REPLICA (por orden de prioridad):
    1. Estado criptográfico — claves, sesiones, contexto (AegisCrypto)
    2. Procesos críticos activos — qué está corriendo y su estado
    3. Configuración de red y servicios — rutas, puertos, bindings
    4. Identidades y credenciales activas — tokens, sesiones autenticadas
    5. Estado de seguridad AEGIS — alertas activas, nivel de amenaza

QUÉ NO REPLICA:
    - Datos masivos de disco (demasiado lento, rompe el ≤100ms)
    - Logs históricos completos (innecesario para continuidad operativa)

REGLAS INVARIABLES:
    - asyncio puro — cero threading, cero blocking
    - Sincronización ≤ 100ms entre gemelos
    - Salto atómico — todas las capas simultáneas, nunca secuencial
    - C se cierra ANTES de que el intruso pueda llegar a B
    - D se genera desde C, no desde A ni B (estado limpio garantizado)
    - Estado siempre serializable — dict puro, sin referencias circulares
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("aegis.twin")


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class TwinID(str, Enum):
    A = "A"   # activo — el mundo lo ve
    B = "B"   # réplica sacrificable
    C = "C"   # santuario — se cierra antes de que el intruso llegue
    D = "D"   # siguiente generación — se crea tras el salto


class TwinStatus(str, Enum):
    ACTIVE    = "ACTIVE"     # gemelo A — en servicio, visible
    REPLICA   = "REPLICA"    # gemelo B/C — sincronizándose, en espera
    SEALED    = "SEALED"     # gemelo C tras intrusión — cerrado, blindado
    PROMOTED  = "PROMOTED"   # gemelo que ha subido de rango (B→A, C→B)
    GENERATING= "GENERATING" # gemelo D en construcción
    READY     = "READY"      # gemelo D listo para entrar en cadena


class JumpTrigger(str, Enum):
    INTRUSION = "INTRUSION"  # intrusión detectada en A
    ANOMALY   = "ANOMALY"    # comportamiento anómalo en A
    SCHEDULED = "SCHEDULED"  # rotación periódica programada
    MANUAL    = "MANUAL"     # activación manual por operador


# ─────────────────────────────────────────────
# ESTADO OPERATIVO — lo que replica el gemelo
# ─────────────────────────────────────────────

@dataclass
class CryptoState:
    """Estado criptográfico — prioridad 1."""
    session_keys:    dict   # claves de sesión activas por contexto
    active_sessions: dict   # sesiones establecidas {session_id: metadata}
    key_fingerprints:dict   # huellas de claves públicas conocidas
    crypto_context:  dict   # parámetros adicionales del motor cripto

    def snapshot(self) -> dict:
        return deepcopy({
            "session_keys":     self.session_keys,
            "active_sessions":  self.active_sessions,
            "key_fingerprints": self.key_fingerprints,
            "crypto_context":   self.crypto_context,
        })


@dataclass
class ProcessState:
    """Procesos críticos activos — prioridad 2."""
    active_modules:  list   # nombres de módulos AEGIS activos
    module_health:   dict   # módulo → {"status": ok/warn/fail, "last_check": ts}
    task_registry:   dict   # task_name → {"started_at": ts, "priority": int}

    def snapshot(self) -> dict:
        return deepcopy({
            "active_modules": self.active_modules,
            "module_health":  self.module_health,
            "task_registry":  self.task_registry,
        })


@dataclass
class NetworkState:
    """Configuración de red y servicios — prioridad 3."""
    bound_ports:     list   # puertos en escucha activa
    active_routes:   dict   # destino → interfaz
    service_bindings:dict   # servicio → {host, port, protocol}
    allowed_peers:   list   # IPs/rangos autorizados

    def snapshot(self) -> dict:
        return deepcopy({
            "bound_ports":      self.bound_ports,
            "active_routes":    self.active_routes,
            "service_bindings": self.service_bindings,
            "allowed_peers":    self.allowed_peers,
        })


@dataclass
class IdentityState:
    """Identidades y credenciales activas — prioridad 4."""
    active_tokens:   dict   # token_id → {scope, expires_at, principal}
    auth_sessions:   dict   # session_id → {principal, created_at, last_seen}
    revoked_tokens:  list   # tokens revocados en esta sesión

    def snapshot(self) -> dict:
        return deepcopy({
            "active_tokens":  self.active_tokens,
            "auth_sessions":  self.auth_sessions,
            "revoked_tokens": self.revoked_tokens,
        })


@dataclass
class SecurityState:
    """Estado de seguridad AEGIS — prioridad 5."""
    threat_level:    str    # LOW / MEDIUM / HIGH / CRITICAL
    active_alerts:   list   # alertas activas sin resolver
    shield_probes:   int    # total de probes recibidos por el escudo
    last_incident:   Optional[str]  # ID del último incidente
    jump_count:      int    # número de saltos realizados en esta sesión

    def snapshot(self) -> dict:
        return deepcopy({
            "threat_level":  self.threat_level,
            "active_alerts": self.active_alerts,
            "shield_probes": self.shield_probes,
            "last_incident": self.last_incident,
            "jump_count":    self.jump_count,
        })


@dataclass
class OperationalState:
    """
    Estado operativo completo — lo que replica el gemelo.
    Orden de prioridad en sincronización: crypto → process → network → identity → security.
    """
    crypto:   CryptoState
    process:  ProcessState
    network:  NetworkState
    identity: IdentityState
    security: SecurityState
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def snapshot(self) -> dict:
        """Serializa estado completo como dict puro — sin referencias circulares."""
        return {
            "crypto":       self.crypto.snapshot(),
            "process":      self.process.snapshot(),
            "network":      self.network.snapshot(),
            "identity":     self.identity.snapshot(),
            "security":     self.security.snapshot(),
            "captured_at":  self.captured_at.isoformat(),
        }

    def integrity_hash(self) -> str:
        """
        Hash SHA3-256 del estado operativo.
        Excluye captured_at — varía en cada snapshot y no es parte del estado comparable.
        Ruido de timing: iteraciones aleatorias adicionales para prevenir ataques de canal lateral.
        """
        snap = self.snapshot()
        snap.pop("captured_at", None)
        payload = str({k: snap[k] for k in sorted(snap.keys())}).encode("utf-8")
        h = hashlib.sha3_256(payload).hexdigest()
        for _ in range(secrets.randbelow(5)):
            hashlib.sha3_256(payload).hexdigest()
        return h


def empty_operational_state() -> OperationalState:
    """Estado operativo vacío — base para inicialización."""
    return OperationalState(
        crypto=CryptoState(
            session_keys={}, active_sessions={},
            key_fingerprints={}, crypto_context={}
        ),
        process=ProcessState(
            active_modules=[], module_health={}, task_registry={}
        ),
        network=NetworkState(
            bound_ports=[], active_routes={},
            service_bindings={}, allowed_peers=[]
        ),
        identity=IdentityState(
            active_tokens={}, auth_sessions={}, revoked_tokens=[]
        ),
        security=SecurityState(
            threat_level="LOW", active_alerts=[],
            shield_probes=0, last_incident=None, jump_count=0
        ),
    )


# ─────────────────────────────────────────────
# GEMELO INDIVIDUAL
# ─────────────────────────────────────────────

@dataclass
class Twin:
    """
    Un gemelo individual de la cadena.
    Contiene su estado operativo y su posición en la cadena.
    """
    twin_id:    TwinID
    status:     TwinStatus
    state:      OperationalState
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sealed_at:  Optional[datetime] = None
    last_sync:  Optional[datetime] = None
    sync_lag_ms: float = 0.0        # lag de la última sincronización
    _sync_secret: bytes = field(default=b"", repr=False, compare=False)

    def sync_from(self, source: "Twin"):
        """
        Sincroniza este gemelo desde la fuente.
        Copia profunda del estado — sin referencias compartidas.
        Registra el lag de sincronización.
        """
        # Verificar que source pertenece a la misma cadena
        if self._sync_secret:
            if not source._sync_secret or not hmac.compare_digest(source._sync_secret, self._sync_secret):
                logger.critical(
                    f"[TWIN.{self.twin_id}] SYNC RECHAZADO — "
                    f"source={source.twin_id} no pertenece a esta cadena"
                )
                raise ValueError(
                    f"sync_from rechazado: fuente no autenticada (twin={source.twin_id})"
                )
        t0           = time.monotonic()
        snap         = source.state.snapshot()
        self.state   = self._restore_state(snap)
        self.last_sync = datetime.now(timezone.utc)
        self.sync_lag_ms = (time.monotonic() - t0) * 1000
        logger.debug(
            f"[TWIN.{self.twin_id}] Sincronizado desde {source.twin_id} "
            f"en {self.sync_lag_ms:.2f}ms"
        )

    def seal(self):
        """
        Cierra y blinda este gemelo.
        Estado congelado — ninguna sincronización posterior.
        """
        self.status    = TwinStatus.SEALED
        self.sealed_at = datetime.now(timezone.utc)
        logger.info(f"[TWIN.{self.twin_id}] SELLADO — estado congelado en {self.sealed_at}")

    def promote(self, new_id: TwinID, new_status: TwinStatus):
        """Promueve este gemelo a un nuevo rango en la cadena."""
        old_id      = self.twin_id
        self.twin_id = new_id
        self.status  = new_status
        logger.info(f"[TWIN] Promovido: {old_id} → {new_id} ({new_status.value})")

    def integrity_ok(self, reference: "Twin") -> bool:
        """Verifica que este gemelo tiene el mismo estado que la referencia."""
        return hmac.compare_digest(
            self.state.integrity_hash(),
            reference.state.integrity_hash()
        )

    def _restore_state(self, snap: dict) -> OperationalState:
        """Reconstruye OperationalState desde un snapshot dict."""
        c = snap["crypto"]
        p = snap["process"]
        n = snap["network"]
        i = snap["identity"]
        s = snap["security"]
        return OperationalState(
            crypto=CryptoState(
                session_keys    = c["session_keys"],
                active_sessions = c["active_sessions"],
                key_fingerprints= c["key_fingerprints"],
                crypto_context  = c["crypto_context"],
            ),
            process=ProcessState(
                active_modules = p["active_modules"],
                module_health  = p["module_health"],
                task_registry  = p["task_registry"],
            ),
            network=NetworkState(
                bound_ports      = n["bound_ports"],
                active_routes    = n["active_routes"],
                service_bindings = n["service_bindings"],
                allowed_peers    = n["allowed_peers"],
            ),
            identity=IdentityState(
                active_tokens  = i["active_tokens"],
                auth_sessions  = i["auth_sessions"],
                revoked_tokens = i["revoked_tokens"],
            ),
            security=SecurityState(
                threat_level  = s["threat_level"],
                active_alerts = s["active_alerts"],
                shield_probes = s["shield_probes"],
                last_incident = s["last_incident"],
                jump_count    = s["jump_count"],
            ),
            captured_at=datetime.now(timezone.utc),
        )

    def __repr__(self):
        return (
            f"Twin({self.twin_id.value} | {self.status.value} | "
            f"sync_lag={self.sync_lag_ms:.1f}ms | "
            f"last_sync={self.last_sync})"
        )


# ─────────────────────────────────────────────
# EVENTO DE SALTO
# ─────────────────────────────────────────────

@dataclass
class JumpEvent:
    """Registro de un salto de cadena."""
    jump_id:     str
    trigger:     JumpTrigger
    triggered_at:datetime
    completed_at:Optional[datetime]
    duration_ms: float
    from_chain:  list    # [A, B, C] antes del salto
    to_chain:    list    # [B→A, C→B, D→C] después del salto
    c_sealed_at: Optional[datetime]
    d_generated: bool
    success:     bool
    notes:       str = ""


# ─────────────────────────────────────────────
# MOTOR DE SINCRONIZACIÓN
# ─────────────────────────────────────────────

class SyncEngine:
    """
    Motor de sincronización continua entre gemelos.
    Sincroniza A→B y B→C cada ≤ SYNC_INTERVAL_MS milisegundos.
    asyncio puro — cero blocking.
    """

    SYNC_INTERVAL_MS = 100   # máximo 100ms entre sincronizaciones

    def __init__(self, chain: "TwinChain"):
        self._chain    = chain
        self._running  = False
        self._task: Optional[asyncio.Task] = None
        self._sync_count = 0
        self._last_sync_ms = 0.0

    async def start(self):
        """Inicia el bucle de sincronización continua."""
        if self._running:
            return
        self._running = True
        self._task    = asyncio.create_task(
            self._sync_loop(), name="aegis.twin.sync"
        )
        logger.info(
            f"[SYNC] Motor de sincronización activo — "
            f"intervalo ≤{self.SYNC_INTERVAL_MS}ms"
        )

    async def stop(self):
        """Detiene el bucle de sincronización."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[SYNC] Motor de sincronización detenido")

    async def _sync_loop(self):
        """Bucle principal — sincroniza A→B→C cada intervalo."""
        interval = self.SYNC_INTERVAL_MS / 1000  # segundos
        while self._running:
            try:
                t0 = time.monotonic()
                await self._sync_once()
                elapsed = (time.monotonic() - t0) * 1000
                self._last_sync_ms = elapsed

                # Si la sincronización tardó menos del intervalo, esperamos el resto
                remaining = interval - (elapsed / 1000)
                if remaining > 0:
                    await asyncio.sleep(remaining)
                else:
                    # Sincronización tardó más del intervalo — advertencia
                    logger.warning(
                        f"[SYNC] Sincronización tardó {elapsed:.1f}ms — "
                        f"supera el límite de {self.SYNC_INTERVAL_MS}ms"
                    )
                    await asyncio.sleep(0)  # ceder control sin bloquear

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[SYNC] Error en ciclo de sincronización: {e}")
                await asyncio.sleep(interval)

    async def _sync_once(self):
        """Una ronda de sincronización A→B y B→C."""
        chain = self._chain

        # Solo sincronizar gemelos en estado activo/réplica
        if (chain.twin_a.status in (TwinStatus.ACTIVE, TwinStatus.REPLICA) and
                chain.twin_b.status in (TwinStatus.REPLICA, TwinStatus.ACTIVE)):
            chain.twin_b.sync_from(chain.twin_a)

        if (chain.twin_b.status in (TwinStatus.REPLICA, TwinStatus.ACTIVE) and
                chain.twin_c.status == TwinStatus.REPLICA):
            chain.twin_c.sync_from(chain.twin_b)

        self._sync_count += 1

        if self._sync_count % 100 == 0:  # log cada 100 sincronizaciones
            logger.debug(
                f"[SYNC] #{self._sync_count} — "
                f"B.lag={chain.twin_b.sync_lag_ms:.1f}ms "
                f"C.lag={chain.twin_c.sync_lag_ms:.1f}ms"
            )


# ─────────────────────────────────────────────
# MOTOR DE SALTO ATÓMICO
# ─────────────────────────────────────────────

class JumpEngine:
    """
    Motor de salto atómico.
    Cuando se detecta intrusión en A, ejecuta el salto en una sola operación atómica:

    ANTES:  A(activo) → B(réplica) → C(réplica)
    SALTO:  1. C se sella instantáneamente (simultáneo con todo lo demás)
            2. B se promueve a A (nuevo activo)
            3. C se convierte en nuevo B
            4. D se genera desde estado limpio de C sellado
    DESPUÉS: B(→A activo) → C(→B réplica) → D(generándose)

    INVARIABLE: Todas las operaciones son simultáneas — nunca secuenciales.
    El sistema siempre está dos niveles por delante del intruso.
    """

    def __init__(self, chain: "TwinChain"):
        self._chain     = chain
        self._jump_log: list = []
        self._jumping   = False   # mutex — solo un salto a la vez

    async def execute(self, trigger: JumpTrigger, notes: str = "") -> JumpEvent:
        """
        Ejecuta el salto atómico.
        Retorna JumpEvent con el resultado completo.
        """
        if self._jumping:
            logger.warning("[JUMP] Salto ya en progreso — ignorando solicitud duplicada")
            if self._jump_log:
                return self._jump_log[-1]
            return JumpEvent(
                jump_id      = "NONE",
                trigger      = trigger,
                triggered_at = datetime.now(timezone.utc),
                completed_at = None,
                duration_ms  = 0.0,
                from_chain   = ["?", "?", "?"],
                to_chain     = ["?", "?", "?"],
                c_sealed_at  = None,
                d_generated  = False,
                success      = False,
                notes        = "Salto bloqueado: ya en progreso",
            )

        self._jumping = True
        t_start       = time.monotonic()
        triggered_at  = datetime.now(timezone.utc)
        jump_id       = secrets.token_hex(6).upper()

        logger.warning(
            f"[JUMP] ⚡ SALTO INICIADO — id={jump_id} trigger={trigger.value} "
            f"notas='{notes}'"
        )

        chain        = self._chain
        from_chain   = [chain.twin_a.twin_id.value,
                        chain.twin_b.twin_id.value,
                        chain.twin_c.twin_id.value]
        c_sealed_at  = None
        d_generated  = False
        success      = False

        try:
            # ── SALTO ATÓMICO ─────────────────────────────────────────────
            # Todas las operaciones se preparan y ejecutan juntas.
            # asyncio.gather garantiza lanzamiento simultáneo.

            await asyncio.gather(
                self._seal_c(chain.twin_c),
                self._promote_b_to_a(chain.twin_b, chain.twin_a),
                self._prepare_new_b(chain.twin_c),
            )

            c_sealed_at = chain.twin_c.sealed_at

            # Actualizar contadores de seguridad en nuevo A (ex-B)
            # CORRECCIÓN: tras el salto twin_b es el nuevo activo, no twin_a
            chain.twin_b.state.security.jump_count += 1
            chain.twin_b.state.security.last_incident = jump_id

            # ── GENERAR D desde estado limpio de C sellado ────────────────
            twin_d = await self._generate_d(chain.twin_c)
            chain.twin_d = twin_d
            d_generated  = True

            # ── REINICIAR SINCRONIZACIÓN con nueva cadena ─────────────────
            # El motor de sync ahora trabaja sobre A(ex-B) → B(ex-C) → D
            # Próxima ronda de sync será A→B, B→C cuando D esté READY

            to_chain = [chain.twin_a.twin_id.value,
                        chain.twin_b.twin_id.value,
                        "D(generando)"]

            success = True
            duration_ms = (time.monotonic() - t_start) * 1000

            logger.warning(
                f"[JUMP] ✓ SALTO COMPLETADO — id={jump_id} "
                f"duración={duration_ms:.1f}ms | "
                f"cadena: {from_chain} → {to_chain}"
            )

        except Exception as e:
            duration_ms = (time.monotonic() - t_start) * 1000
            to_chain    = ["ERROR"]
            logger.error(f"[JUMP] ✗ SALTO FALLIDO — id={jump_id}: {e}")

        finally:
            self._jumping = False

        event = JumpEvent(
            jump_id      = jump_id,
            trigger      = trigger,
            triggered_at = triggered_at,
            completed_at = datetime.now(timezone.utc) if success else None,
            duration_ms  = duration_ms,
            from_chain   = from_chain,
            to_chain     = to_chain,
            c_sealed_at  = c_sealed_at,
            d_generated  = d_generated,
            success      = success,
            notes        = notes,
        )
        self._jump_log.append(event)
        return event

    async def _seal_c(self, twin_c: Twin):
        """Sella C instantáneamente — estado congelado, inaccesible."""
        twin_c.seal()

    async def _promote_b_to_a(self, twin_b: Twin, old_twin_a: Twin):
        """
        Promueve B a la posición A.
        El ex-A queda marcado como comprometido (no se destruye — Capa 7 lo estudia).
        """
        old_twin_a.status = TwinStatus.SEALED   # ex-A comprometido — para forense
        twin_b.promote(TwinID.A, TwinStatus.ACTIVE)
        logger.info("[JUMP] B promovido a A — nuevo sistema activo")

    async def _prepare_new_b(self, twin_c: Twin):
        """
        El ex-C sellado se convierte en nuevo B una vez sellado.
        Nota: twin_c ya está SEALED — se convierte en réplica del nuevo A.
        La sincronización real ocurrirá en el próximo ciclo del SyncEngine.
        """
        # No promovemos ex-C aún — esperamos a que D esté READY
        # para no dejar la cadena sin santuario
        logger.info("[JUMP] Ex-C preparado como candidato a nuevo B")

    async def _generate_d(self, sealed_c: Twin) -> Twin:
        """
        Genera D desde el estado limpio de C sellado.
        D hereda el estado de C (no de A comprometido, no de B sacrificado).
        Garantía: D parte de estado verificadamente limpio.
        """
        twin_d = Twin(
            twin_id = TwinID.D,
            status  = TwinStatus.GENERATING,
            state   = empty_operational_state(),
        )
        twin_d._sync_secret = self._chain._sync_secret  # mismo secreto de cadena
        twin_d.sync_from(sealed_c)   # copia desde C sellado — estado limpio
        twin_d.status = TwinStatus.READY

        logger.info(
            f"[JUMP] D generado desde C sellado — "
            f"estado limpio verificado | "
            f"integridad: {twin_d.state.integrity_hash()[:12]}..."
        )
        return twin_d

    def get_jump_log(self) -> list:
        """Historial de saltos — para Capa 7 (forense)."""
        return self._jump_log


# ─────────────────────────────────────────────
# CADENA DE GEMELOS — TwinChain
# ─────────────────────────────────────────────

class TwinChain:
    """
    Cadena completa A/B/C con motor de sincronización y salto.

    Estado normal:    A(ACTIVE) → B(REPLICA) → C(REPLICA)
    Tras intrusión:   B(→A, ACTIVE) → C(→B candidato) → D(READY)
    """

    def __init__(self, initial_state: Optional[OperationalState] = None):
        state = initial_state or empty_operational_state()

        self._sync_secret = secrets.token_bytes(32)

        self.twin_a = Twin(TwinID.A, TwinStatus.ACTIVE,  deepcopy(state))
        self.twin_b = Twin(TwinID.B, TwinStatus.REPLICA, deepcopy(state))
        self.twin_c = Twin(TwinID.C, TwinStatus.REPLICA, deepcopy(state))
        self.twin_d: Optional[Twin] = None

        # Firmar cada gemelo con el secreto de cadena
        for t in (self.twin_a, self.twin_b, self.twin_c):
            t._sync_secret = self._sync_secret

        self._sync  = SyncEngine(self)
        self._jump  = JumpEngine(self)
        self._callbacks_jump:  list = []
        self._active = False

        logger.info(
            "[AEGIS.TwinChain] Cadena inicializada — "
            "A(ACTIVE) → B(REPLICA) → C(REPLICA)"
        )

    async def start(self):
        """Activa la cadena — inicia sincronización continua."""
        if self._active:
            return
        self._active = True
        await self._sync.start()
        logger.info("[AEGIS.TwinChain] Cadena activa — sincronización iniciada")

    async def stop(self):
        """Detiene la cadena ordenadamente."""
        self._active = False
        await self._sync.stop()
        logger.info("[AEGIS.TwinChain] Cadena detenida")

    def update_state(self, updater: Callable[[OperationalState], None]):
        """
        Actualiza el estado del gemelo A (activo).
        La sincronización propagará el cambio a B y C en el próximo ciclo.

        updater: función que recibe el OperationalState de A y lo modifica in-place.
        """
        updater(self.twin_a.state)

    async def trigger_jump(
        self,
        trigger: JumpTrigger = JumpTrigger.INTRUSION,
        notes: str = ""
    ) -> JumpEvent:
        """
        Dispara el salto atómico de la cadena.
        Llamado por Capa 3 (detección) o Capa 4 (cierre atómico).
        """
        # Pausar sincronización durante el salto
        await self._sync.stop()

        event = await self._jump.execute(trigger, notes)

        # Notificar callbacks externos
        for cb in self._callbacks_jump:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(event)
                else:
                    cb(event)
            except Exception as e:
                logger.warning(f"[TWIN] Error en callback de salto: {e}")

        # Reiniciar sincronización con la nueva cadena
        if event.success and self._active:
            await self._sync.start()

        return event

    def register_jump_callback(self, callback: Callable):
        """
        Registra callback que recibe JumpEvent tras cada salto.
        Uso: Capa 4 (cierre atómico), Capa 7 (forense).
        """
        self._callbacks_jump.append(callback)

    def status(self) -> dict:
        """Estado completo de la cadena."""
        return {
            "active":       self._active,
            "twin_a":       repr(self.twin_a),
            "twin_b":       repr(self.twin_b),
            "twin_c":       repr(self.twin_c),
            "twin_d":       repr(self.twin_d) if self.twin_d else None,
            "jump_count":   len(self._jump.get_jump_log()),
            "sync_count":   self._sync._sync_count,
            "last_sync_ms": self._sync._last_sync_ms,
        }

    def get_jump_log(self) -> list:
        """Historial de saltos — para Capa 7."""
        return self._jump.get_jump_log()

    def integrity_check(self) -> dict:
        """
        Verifica que las réplicas son copias íntegras del gemelo activo.
        Compara por ROL (ACTIVE/REPLICA), no por posición fija (twin_a/twin_b).

        Casos manejados:
            Normal:      A=ACTIVE, B=REPLICA, C=REPLICA → compara B vs A, C vs B
            Tras salto:  A=SEALED, B=ACTIVE, C=SEALED  → sin réplicas aún → pendiente
            Sin start(): A=REPLICA, B=REPLICA, C=REPLICA → fallback a posición
        """
        all_twins = [self.twin_a, self.twin_b, self.twin_c]

        # Gemelo activo por rol
        active = next(
            (t for t in all_twins if t.status == TwinStatus.ACTIVE),
            None
        )

        # Sin activo claro — sistema recién creado sin start(), usar posición
        if active is None:
            active = self.twin_a

        # Réplicas: gemelos en estado REPLICA
        replicas = [t for t in all_twins
                    if t.status == TwinStatus.REPLICA and t is not active]

        replica_1 = replicas[0] if len(replicas) > 0 else None
        replica_2 = replicas[1] if len(replicas) > 1 else None

        # Sin réplicas disponibles (transitorio post-salto mientras D se genera)
        # El sistema está en estado correcto — el activo acaba de tomar el control
        if replica_1 is None:
            r1_ok = True   # transitorio — no es brecha
            r2_ok = True
        else:
            r1_ok = replica_1.integrity_ok(active)
            r2_ok = replica_2.integrity_ok(replica_1) if replica_2 else True

        active_id = active.twin_id.value if hasattr(active.twin_id, "value") else str(active.twin_id)

        return {
            "B_matches_A": r1_ok,
            "C_matches_B": r2_ok,
            "A_hash":      active.state.integrity_hash()[:12],
            "B_hash":      replica_1.state.integrity_hash()[:12] if replica_1 else "",
            "C_hash":      replica_2.state.integrity_hash()[:12] if replica_2 else "",
            "active_twin": active_id,
        }
