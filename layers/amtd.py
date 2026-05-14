"""
AEGIS — Capa 5: Superficie Móvil AMTD
========================================
Autonomous Moving Target Defense.

FILOSOFÍA:
    El atacante necesita tiempo entre reconocimiento y ataque.
    Si la superficie cambia antes de que pueda actuar — su reconocimiento
    caduca y tiene que empezar de cero. Indefinidamente.

    No es ocultación — es movimiento continuo.
    El sistema legítimo sigue funcionando. El atacante pierde el mapa.

QUÉ SE MUEVE:
    Puertos    — los servicios reales rotan entre rangos predefinidos
    Rutas      — los endpoints cambian de path periódicamente
    Tokens     — identificadores de sesión rotan antes de que caduquen
    Estructura — el fingerprint del sistema cambia cada ciclo

PARÁMETROS:
    Intervalo de rotación: configurable — default 30 segundos
    Reconocimiento caduca en: < intervalo de rotación
    Movimiento: determinista con semilla secreta — el sistema legítimo
                siempre sabe dónde está todo

CONECTORES:
    → Capa 0.5 (shield): notifica nuevos puertos señuelo tras rotación
    → Capa 3 (detector): cualquier acceso a ruta/puerto caducado = intruso
    → Capa 7 (forensics): log de rotaciones para análisis
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("aegis.amtd")


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class RotationType(str, Enum):
    PORT      = "PORT"       # rotación de puertos
    ROUTE     = "ROUTE"      # rotación de rutas/endpoints
    TOKEN     = "TOKEN"      # rotación de tokens de sesión
    STRUCTURE = "STRUCTURE"  # rotación de fingerprint estructural


class AMTDStatus(str, Enum):
    IDLE     = "IDLE"
    ACTIVE   = "ACTIVE"
    ROTATING = "ROTATING"


# ─────────────────────────────────────────────
# EVENTO DE ROTACIÓN
# ─────────────────────────────────────────────

@dataclass
class RotationEvent:
    """Registro de una rotación de superficie."""
    rotation_id:   str
    timestamp:     datetime
    rotation_type: RotationType
    previous:      dict    # estado anterior
    current:       dict    # estado actual
    cycle:         int     # número de ciclo desde arranque

    def to_dict(self) -> dict:
        return {
            "rotation_id":   self.rotation_id,
            "timestamp":     self.timestamp.isoformat(),
            "rotation_type": self.rotation_type.value,
            "previous":      self.previous,
            "current":       self.current,
            "cycle":         self.cycle,
        }


# ─────────────────────────────────────────────
# MOTOR DE PUERTOS — rotación de puertos de servicio
# ─────────────────────────────────────────────

class PortRotationEngine:
    """
    Rota los puertos de servicio periódicamente.
    Los puertos anteriores se convierten en señuelos detectores:
    cualquier acceso a un puerto caducado = intruso que usó reconocimiento viejo.

    Determinista: dado el mismo ciclo y semilla, siempre produce los mismos puertos.
    El sistema legítimo puede recalcular en cualquier momento.
    """

    # Rangos de puertos disponibles para rotación
    # Separados de puertos estándar para no interferir con servicios del SO
    PORT_RANGES = [
        (8100, 8199),   # HTTP alternativo
        (8200, 8299),   # HTTPS alternativo
        (9100, 9199),   # servicios internos A
        (9200, 9299),   # servicios internos B
        (7100, 7199),   # servicios internos C
    ]

    def __init__(self, seed: bytes, num_ports: int = 3):
        self._seed      = seed
        self._num_ports = num_ports
        self._cycle     = 0
        self._current:  list = []
        self._previous: list = []
        self._rotate()   # inicializar en primer ciclo

    def _derive_ports(self, cycle: int) -> list:
        """
        Deriva puertos deterministas para un ciclo dado.
        Misma semilla + mismo ciclo = mismos puertos.
        El sistema legítimo puede recalcular en cualquier momento.
        """
        ports = []
        for i, (low, high) in enumerate(self.PORT_RANGES[:self._num_ports]):
            key     = hmac.new(
                self._seed,
                f"port:{cycle}:{i}".encode(),
                hashlib.sha256
            ).digest()
            offset  = int.from_bytes(key[:2], "big") % (high - low)
            ports.append(low + offset)
        return ports

    def _rotate(self):
        self._previous = list(self._current)
        self._current  = self._derive_ports(self._cycle)
        self._cycle   += 1

    def rotate(self) -> tuple:
        """Ejecuta una rotación. Retorna (previous_ports, current_ports)."""
        self._rotate()
        logger.debug(
            f"[AMTD.PORT] Ciclo {self._cycle} — "
            f"anterior={self._previous} actual={self._current}"
        )
        return self._previous, self._current

    @property
    def current_ports(self) -> list:
        return list(self._current)

    @property
    def previous_ports(self) -> list:
        return list(self._previous)

    def is_stale(self, port: int) -> bool:
        """True si el puerto pertenece al ciclo anterior — reconocimiento caducado."""
        return port in self._previous and port not in self._current

    def is_active(self, port: int) -> bool:
        return port in self._current

    @property
    def cycle(self) -> int:
        return self._cycle


# ─────────────────────────────────────────────
# MOTOR DE RUTAS — rotación de endpoints
# ─────────────────────────────────────────────

class RouteRotationEngine:
    """
    Rota las rutas de los endpoints del sistema.
    Las rutas anteriores se convierten en señuelos:
    acceder a una ruta caducada = reconocimiento viejo = intruso.
    """

    # Plantillas de ruta — el segmento variable rota en cada ciclo
    ROUTE_TEMPLATES = [
        "/api/{token}/data",
        "/api/{token}/status",
        "/internal/{token}/health",
        "/svc/{token}/metrics",
        "/v2/{token}/config",
    ]

    def __init__(self, seed: bytes):
        self._seed     = seed
        self._cycle    = 0
        self._current: dict = {}   # template → ruta activa
        self._previous:dict = {}   # template → ruta del ciclo anterior
        self._rotate()

    def _derive_token(self, template: str, cycle: int) -> str:
        """Token de ruta determinista para un ciclo dado."""
        key = hmac.new(
            self._seed,
            f"route:{template}:{cycle}".encode(),
            hashlib.sha256
        ).digest()
        return key[:6].hex()   # 12 caracteres hex

    def _rotate(self):
        self._previous = dict(self._current)
        self._current  = {
            t: t.replace("{token}", self._derive_token(t, self._cycle))
            for t in self.ROUTE_TEMPLATES
        }
        self._cycle += 1

    def rotate(self) -> tuple:
        """Retorna (rutas_anteriores, rutas_actuales)."""
        self._rotate()
        logger.debug(f"[AMTD.ROUTE] Ciclo {self._cycle} — {len(self._current)} rutas rotadas")
        return self._previous, self._current

    @property
    def current_routes(self) -> dict:
        return dict(self._current)

    @property
    def previous_routes(self) -> dict:
        return dict(self._previous)

    def is_stale(self, path: str) -> bool:
        """True si la ruta es del ciclo anterior."""
        return path in self._previous.values() and path not in self._current.values()

    def is_active(self, path: str) -> bool:
        return path in self._current.values()

    def get_active_route(self, template: str) -> Optional[str]:
        return self._current.get(template)

    @property
    def cycle(self) -> int:
        return self._cycle


# ─────────────────────────────────────────────
# MOTOR DE TOKENS — rotación de identificadores de sesión
# ─────────────────────────────────────────────

class TokenRotationEngine:
    """
    Rota los tokens de sesión antes de que caduquen.
    Un atacante que capture un token de sesión lo tiene por tiempo limitado.
    Tras la rotación, el token capturado es inútil.
    """

    def __init__(self, seed: bytes, token_lifetime_cycles: int = 2):
        self._seed             = seed
        self._lifetime_cycles  = token_lifetime_cycles
        self._cycle            = 0
        self._active_tokens:   dict = {}   # token → {created_cycle, session_id}
        self._revoked_tokens:  set  = set()

    def issue_token(self, session_id: str) -> str:
        """Emite un nuevo token para una sesión."""
        raw   = hmac.new(
            self._seed,
            f"token:{session_id}:{self._cycle}:{secrets.token_hex(8)}".encode(),
            hashlib.sha256
        ).digest()
        token = raw.hex()
        self._active_tokens[token] = {
            "session_id":    session_id,
            "created_cycle": self._cycle,
        }
        return token

    def rotate(self) -> tuple:
        """
        Rota tokens — revoca los que han superado su lifetime.
        Retorna (tokens_revocados, tokens_activos).
        """
        self._cycle  += 1
        to_revoke     = []
        for token, meta in list(self._active_tokens.items()):
            age = self._cycle - meta["created_cycle"]
            if age >= self._lifetime_cycles:
                to_revoke.append(token)

        for token in to_revoke:
            self._revoked_tokens.add(token)
            del self._active_tokens[token]

        logger.debug(
            f"[AMTD.TOKEN] Ciclo {self._cycle} — "
            f"revocados={len(to_revoke)} activos={len(self._active_tokens)}"
        )
        return to_revoke, list(self._active_tokens.keys())

    def is_valid(self, token: str) -> bool:
        return token in self._active_tokens

    def is_revoked(self, token: str) -> bool:
        return token in self._revoked_tokens

    def renew(self, old_token: str) -> Optional[str]:
        """Renueva un token activo — emite nuevo y revoca el viejo."""
        meta = self._active_tokens.get(old_token)
        if not meta:
            return None
        new_token = self.issue_token(meta["session_id"])
        self._revoked_tokens.add(old_token)
        del self._active_tokens[old_token]
        return new_token

    @property
    def cycle(self) -> int:
        return self._cycle

    def active_count(self) -> int:
        return len(self._active_tokens)


# ─────────────────────────────────────────────
# MOTOR DE ESTRUCTURA — rotación de fingerprint del sistema
# ─────────────────────────────────────────────

class StructureRotationEngine:
    """
    Cambia el fingerprint observable del sistema en cada ciclo.
    Cabeceras de respuesta, versiones declaradas, identificadores
    de servicio — todo cambia para que el atacante no pueda
    construir un perfil estable del sistema objetivo.
    """

    FAKE_SERVERS   = ["nginx/1.24.0", "Apache/2.4.57", "cloudflare", "AmazonS3"]
    FAKE_POWERED   = ["PHP/8.2.0", "ASP.NET", "Express", "Django/4.2"]
    FAKE_VERSIONS  = ["v2.1.0", "v3.0.1", "v1.9.5", "v4.2.0"]

    def __init__(self, seed: bytes):
        self._seed     = seed
        self._cycle    = 0
        self._current: dict = {}
        self._previous:dict = {}
        self._rotate()

    def _derive_structure(self, cycle: int) -> dict:
        def pick(lst, label):
            key = hmac.new(
                self._seed,
                f"struct:{label}:{cycle}".encode(),
                hashlib.sha256
            ).digest()
            return lst[int.from_bytes(key[:2], "big") % len(lst)]

        return {
            "Server":       pick(self.FAKE_SERVERS,  "server"),
            "X-Powered-By": pick(self.FAKE_POWERED,  "powered"),
            "X-API-Version":pick(self.FAKE_VERSIONS, "version"),
            "X-Request-ID": hashlib.sha256(
                self._seed + f"reqid:{cycle}".encode()
            ).hexdigest()[:12],
        }

    def _rotate(self):
        self._previous = dict(self._current)
        self._current  = self._derive_structure(self._cycle)
        self._cycle   += 1

    def rotate(self) -> tuple:
        self._rotate()
        logger.debug(f"[AMTD.STRUCT] Ciclo {self._cycle} — estructura rotada")
        return self._previous, self._current

    @property
    def current_headers(self) -> dict:
        return dict(self._current)

    @property
    def previous_headers(self) -> dict:
        return dict(self._previous)

    def fingerprint_changed(self) -> bool:
        """True si la estructura actual es distinta de la anterior."""
        return self._current != self._previous

    @property
    def cycle(self) -> int:
        return self._cycle


# ─────────────────────────────────────────────
# FACHADA PRINCIPAL — AegisAMTD
# ─────────────────────────────────────────────

class AegisAMTD:
    """
    Fachada de Capa 5 — Superficie Móvil AMTD.
    Orquesta los cuatro motores de rotación en ciclos simultáneos.

    Uso:
        amtd = AegisAMTD(rotation_interval_s=30)
        amtd.register_stale_access_callback(detector.on_stale_access)
        amtd.register_rotation_callback(forensics.on_rotation)
        await amtd.start()
        ...
        await amtd.stop()

    Consultas:
        amtd.current_ports()         → puertos activos ahora
        amtd.current_routes()        → rutas activas ahora
        amtd.is_stale_port(port)     → True si el puerto es de reconocimiento viejo
        amtd.is_stale_route(path)    → True si la ruta es de reconocimiento viejo
        amtd.is_valid_token(token)   → True si el token sigue activo
    """

    DEFAULT_INTERVAL = 30   # segundos entre rotaciones

    def __init__(
        self,
        rotation_interval_s: int  = DEFAULT_INTERVAL,
        seed:                bytes = None,
        num_ports:           int   = 3,
    ):
        # Semilla maestra — derivamos una por motor para independencia
        self._master_seed   = seed or secrets.token_bytes(32)
        self._interval      = rotation_interval_s
        self._status        = AMTDStatus.IDLE
        self._cycle         = 0
        self._task:         Optional[asyncio.Task] = None
        self._rotation_log: list = []

        # Derivar semillas independientes por motor
        def derive_seed(label: str) -> bytes:
            return hmac.new(self._master_seed, label.encode(), hashlib.sha256).digest()

        self._port_engine   = PortRotationEngine(derive_seed("ports"),     num_ports)
        self._route_engine  = RouteRotationEngine(derive_seed("routes"))
        self._token_engine  = TokenRotationEngine(derive_seed("tokens"))
        self._struct_engine = StructureRotationEngine(derive_seed("struct"))

        # Callbacks
        self._stale_callbacks:    list = []   # → Capa 3: acceso a superficie caducada
        self._rotation_callbacks: list = []   # → Capa 7: log de rotaciones

        logger.info(
            f"[AEGIS.AMTD] Capa 5 inicializada — "
            f"intervalo={rotation_interval_s}s | "
            f"puertos={num_ports} | motores=4"
        )

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def register_stale_access_callback(self, cb: Callable):
        """
        Capa 3 — llamado cuando alguien accede a superficie caducada.
        Recibe: {"type": "port"|"route", "value": ..., "cycle": ...}
        """
        self._stale_callbacks.append(cb)

    def register_rotation_callback(self, cb: Callable):
        """Capa 7 — recibe RotationEvent tras cada ciclo."""
        self._rotation_callbacks.append(cb)

    # ── Ciclo de vida ─────────────────────────────────────────────────────────

    async def start(self):
        """Inicia el bucle de rotación continua."""
        if self._status == AMTDStatus.ACTIVE:
            return
        self._status = AMTDStatus.ACTIVE
        self._task   = asyncio.create_task(
            self._rotation_loop(), name="aegis.amtd.rotation"
        )
        logger.info(
            f"[AMTD] Motor de rotación activo — "
            f"ciclo cada {self._interval}s"
        )

    async def stop(self):
        """Detiene el bucle de rotación."""
        self._status = AMTDStatus.IDLE
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[AMTD] Motor de rotación detenido")

    async def rotate_now(self):
        """Fuerza una rotación inmediata — para tests o respuesta a amenaza."""
        await self._execute_rotation()

    async def _rotation_loop(self):
        """Bucle principal — ejecuta rotación cada intervalo."""
        while self._status == AMTDStatus.ACTIVE:
            try:
                await asyncio.sleep(self._interval)
                await self._execute_rotation()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[AMTD] Error en ciclo de rotación: {e}")

    async def _execute_rotation(self):
        """
        Ejecuta todos los motores de rotación simultáneamente.
        asyncio.gather() — todos a la vez, nunca secuencial.
        """
        self._status = AMTDStatus.ROTATING
        self._cycle += 1
        t0           = time.monotonic()

        # Rotar todos los motores simultáneamente
        (
            (prev_ports,  curr_ports),
            (prev_routes, curr_routes),
            (prev_tokens, curr_tokens),
            (prev_struct, curr_struct),
        ) = await asyncio.gather(
            self._async_rotate_ports(),
            self._async_rotate_routes(),
            self._async_rotate_tokens(),
            self._async_rotate_struct(),
        )

        elapsed_ms = (time.monotonic() - t0) * 1000
        self._status = AMTDStatus.ACTIVE

        # Registrar eventos de rotación
        events = [
            RotationEvent(
                rotation_id   = f"{self._cycle}-PORT",
                timestamp     = datetime.now(timezone.utc),
                rotation_type = RotationType.PORT,
                previous      = {"ports": prev_ports},
                current       = {"ports": curr_ports},
                cycle         = self._cycle,
            ),
            RotationEvent(
                rotation_id   = f"{self._cycle}-ROUTE",
                timestamp     = datetime.now(timezone.utc),
                rotation_type = RotationType.ROUTE,
                previous      = prev_routes,
                current       = curr_routes,
                cycle         = self._cycle,
            ),
            RotationEvent(
                rotation_id   = f"{self._cycle}-TOKEN",
                timestamp     = datetime.now(timezone.utc),
                rotation_type = RotationType.TOKEN,
                previous      = {"revoked": prev_tokens},
                current       = {"active_count": len(curr_tokens)},
                cycle         = self._cycle,
            ),
            RotationEvent(
                rotation_id   = f"{self._cycle}-STRUCT",
                timestamp     = datetime.now(timezone.utc),
                rotation_type = RotationType.STRUCTURE,
                previous      = prev_struct,
                current       = curr_struct,
                cycle         = self._cycle,
            ),
        ]
        self._rotation_log.extend(events)

        # Notificar callbacks de rotación (Capa 7) — simultáneamente
        if self._rotation_callbacks:
            await asyncio.gather(*[
                self._call(cb, event)
                for event in events
                for cb in self._rotation_callbacks
            ])

        logger.info(
            f"[AMTD] Ciclo {self._cycle} completado en {elapsed_ms:.2f}ms — "
            f"puertos: {prev_ports}→{curr_ports}"
        )

    async def _async_rotate_ports(self) -> tuple:
        prev, curr = self._port_engine.rotate()
        return prev, curr

    async def _async_rotate_routes(self) -> tuple:
        prev, curr = self._route_engine.rotate()
        return prev, curr

    async def _async_rotate_tokens(self) -> tuple:
        revoked, active = self._token_engine.rotate()
        return revoked, active

    async def _async_rotate_struct(self) -> tuple:
        prev, curr = self._struct_engine.rotate()
        return prev, curr

    async def _call(self, cb: Callable, arg):
        try:
            if asyncio.iscoroutinefunction(cb):
                await cb(arg)
            else:
                cb(arg)
        except Exception as e:
            logger.warning(f"[AMTD] Error en callback: {e}")

    # ── Detección de acceso a superficie caducada ─────────────────────────────

    async def check_port(self, port: int, source_ip: str = "") -> bool:
        """
        Verifica si un puerto accedido es activo o caducado.
        Si es caducado → notifica a Capa 3 (reconocimiento viejo detectado).
        Retorna True si el puerto es activo, False si está caducado.
        """
        if self._port_engine.is_stale(port):
            logger.warning(
                f"[AMTD] Puerto caducado accedido: {port} "
                f"desde {source_ip} — reconocimiento obsoleto detectado"
            )
            await self._notify_stale("port", port, source_ip)
            return False
        return self._port_engine.is_active(port)

    async def check_route(self, path: str, source_ip: str = "") -> bool:
        """
        Verifica si una ruta accedida es activa o caducada.
        Si es caducada → notifica a Capa 3.
        """
        if self._route_engine.is_stale(path):
            logger.warning(
                f"[AMTD] Ruta caducada accedida: {path} "
                f"desde {source_ip} — reconocimiento obsoleto detectado"
            )
            await self._notify_stale("route", path, source_ip)
            return False
        return self._route_engine.is_active(path)

    async def _notify_stale(self, surface_type: str, value, source_ip: str):
        """Notifica acceso a superficie caducada — Capa 3."""
        payload = {
            "type":      surface_type,
            "value":     value,
            "cycle":     self._cycle,
            "source_ip": source_ip,
        }
        if self._stale_callbacks:
            await asyncio.gather(*[self._call(cb, payload) for cb in self._stale_callbacks])

    # ── Consultas de estado actual ────────────────────────────────────────────

    def current_ports(self) -> list:
        return self._port_engine.current_ports

    def previous_ports(self) -> list:
        return self._port_engine.previous_ports

    def current_routes(self) -> dict:
        return self._route_engine.current_routes

    def previous_routes(self) -> dict:
        return self._route_engine.previous_routes

    def current_headers(self) -> dict:
        return self._struct_engine.current_headers

    def is_stale_port(self, port: int) -> bool:
        return self._port_engine.is_stale(port)

    def is_active_port(self, port: int) -> bool:
        return self._port_engine.is_active(port)

    def is_stale_route(self, path: str) -> bool:
        return self._route_engine.is_stale(path)

    def is_active_route(self, path: str) -> bool:
        return self._route_engine.is_active(path)

    # ── Gestión de tokens ─────────────────────────────────────────────────────

    def issue_token(self, session_id: str) -> str:
        return self._token_engine.issue_token(session_id)

    def is_valid_token(self, token: str) -> bool:
        return self._token_engine.is_valid(token)

    def is_revoked_token(self, token: str) -> bool:
        return self._token_engine.is_revoked(token)

    def renew_token(self, old_token: str) -> Optional[str]:
        return self._token_engine.renew(old_token)

    # ── Log y estado ──────────────────────────────────────────────────────────

    def get_rotation_log(self) -> list:
        return [e.to_dict() for e in self._rotation_log]

    def status(self) -> dict:
        return {
            "status":          self._status.value,
            "cycle":           self._cycle,
            "interval_s":      self._interval,
            "current_ports":   self.current_ports(),
            "active_routes":   len(self.current_routes()),
            "active_tokens":   self._token_engine.active_count(),
            "total_rotations": len(self._rotation_log),
        }
