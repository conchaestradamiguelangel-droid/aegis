"""
AEGIS — Capa 0.5: Escudo Disuasorio
=====================================
Primera línea visible exterior de AEGIS.
Filosofía: NO invisibilidad — proyección de coste alto.

El atacante oportunista debe percibir:
  - "Este sistema me ha visto"
  - "Este sistema está monitorizando activamente"
  - "El coste de entrar aquí es mayor que el beneficio"

Si decide no entrar → objetivo cumplido sin activar nada más.
Si entra igualmente → capas interiores se activan (Capa 1+).

TRES NIVELES SIMULTÁNEOS:
  Nivel 1 — Red:         Firmas de monitorización activa en respuestas
  Nivel 2 — Servicios:   Puertos/servicios visibles con señales de detección
  Nivel 3 — Comportamiento: Registro de exploración + confirmación de detección

REGLAS:
  - 100% defensivo — nunca contraataca
  - Nunca oculta que existe — al contrario, se hace visible como sistema vigilado
  - Cada contacto exterior queda registrado con fingerprint del explorador
  - Pasa alertas a Capa 3 (detección) y Capa 7 (forense) cuando están activas
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import socket
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

logger = logging.getLogger("aegis.shield")


# ─────────────────────────────────────────────
# ENUMS Y CONSTANTES
# ─────────────────────────────────────────────

class ThreatLevel(str, Enum):
    LOW    = "LOW"     # ping, escaneo pasivo de un puerto
    MEDIUM = "MEDIUM"  # escaneo de múltiples puertos, petición inusual
    HIGH   = "HIGH"    # escaneo agresivo, patrones de reconocimiento conocidos


class ProbeType(str, Enum):
    TCP_CONNECT   = "TCP_CONNECT"    # intento de conexión TCP
    HTTP_REQUEST  = "HTTP_REQUEST"   # petición HTTP a servicio señuelo
    PORT_SCAN     = "PORT_SCAN"      # múltiples puertos en ráfaga
    BANNER_GRAB   = "BANNER_GRAB"    # intento de leer banner de servicio
    UNKNOWN       = "UNKNOWN"        # contacto no clasificado


# Mensajes de banner disuasorio — lo que ve el atacante al conectar
# Diseñados para comunicar: "te hemos visto, esto es una trampa monitorizada"
BANNERS_DISUASORIOS = [
    (
        "AEGIS Security Monitor v3.2 | Active Intrusion Detection Enabled\r\n"
        "WARNING: This system is under continuous monitoring.\r\n"
        "All connection attempts are logged, fingerprinted and reported.\r\n"
        "Unauthorized access attempts will be prosecuted.\r\n"
        "Your session ID: {session_id}\r\n"
    ),
    (
        "*** MONITORED SYSTEM — ACTIVE THREAT DETECTION ONLINE ***\r\n"
        "Connection registered. Source fingerprint captured.\r\n"
        "Security team has been notified of this probe attempt.\r\n"
        "Session: {session_id}\r\n"
    ),
    (
        "SECURITY NOTICE: Intrusion Detection System Active\r\n"
        "This connection has been logged with full forensic capture.\r\n"
        "Incident ID: {session_id} — Do not proceed.\r\n"
    ),
]

# Headers HTTP disuasorios — lo que ve el atacante en respuestas HTTP
HEADERS_DISUASORIOS = {
    "X-Security-Monitor":    "AEGIS-Active",
    "X-Intrusion-Detection": "Enabled",
    "X-Probe-Detected":      "True",
    "X-Forensic-Capture":    "Active",
    "X-Incident-ID":         "{session_id}",
    "X-Warning":             "All-requests-logged-and-fingerprinted",
    "Server":                "AEGIS-Monitored-System/3.2",
}

# Cuerpo de respuesta HTTP disuasoria
HTTP_BODY_DISUASORIO = (
    "<!DOCTYPE html><html><head><title>Security Monitor</title></head><body>"
    "<h1>AEGIS Security Monitor</h1>"
    "<p><strong>WARNING:</strong> This system operates under active intrusion detection.</p>"
    "<p>Your connection attempt has been logged, fingerprinted and flagged.</p>"
    "<p>Incident reference: <code>{session_id}</code></p>"
    "<p>Unauthorized access is monitored and reported.</p>"
    "</body></html>\r\n"
)


# ─────────────────────────────────────────────
# DATACLASSES
# ─────────────────────────────────────────────

@dataclass
class ProbeEvent:
    """Registro de un contacto exterior con el escudo."""
    probe_id:      str
    timestamp:     datetime
    source_ip:     str
    source_port:   int
    target_port:   int
    probe_type:    ProbeType
    threat_level:  ThreatLevel
    fingerprint:   str            # hash del perfil del explorador
    raw_data:      bytes          # primeros bytes recibidos (para análisis)
    response_sent: str            # qué banner/respuesta se envió
    duration_ms:   float = 0.0    # tiempo que mantuvo conexión abierta

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"]   = self.timestamp.isoformat()
        d["probe_type"]  = self.probe_type.value
        d["threat_level"] = self.threat_level.value
        d["raw_data"]    = self.raw_data.hex()
        return d


@dataclass
class ShieldStatus:
    """Estado actual del escudo disuasorio."""
    active:           bool
    level1_active:    bool   # red
    level2_active:    bool   # servicios
    level3_active:    bool   # comportamiento
    ports_monitored:  list
    total_probes:     int
    probes_last_hour: int
    last_probe_at:    Optional[datetime]
    started_at:       datetime


# ─────────────────────────────────────────────
# NIVEL 1 — RED: Firmas de monitorización activa
# ─────────────────────────────────────────────

class NetworkSignatureLayer:
    """
    Nivel 1 — Red.
    Genera y adjunta firmas en todas las respuestas que indican
    monitorización activa. El atacante ve evidencia de detección
    desde el primer paquete.
    """

    def __init__(self):
        # Firma única de esta instancia AEGIS — cambia en cada arranque
        self._instance_sig = secrets.token_hex(8).upper()
        logger.info(f"[SHIELD.L1] Firma de instancia: AEGIS-{self._instance_sig}")

    def build_tcp_banner(self, session_id: str) -> bytes:
        """
        Construye el banner TCP disuasorio.
        Rota entre los banners disponibles según el session_id
        para parecer dinámico y no estático/scripteable.
        """
        idx    = int(hashlib.sha256(session_id.encode()).hexdigest(), 16) % len(BANNERS_DISUASORIOS)
        banner = BANNERS_DISUASORIOS[idx].format(session_id=session_id)
        return banner.encode("utf-8")

    def build_http_response(self, session_id: str, status: int = 403) -> bytes:
        """
        Construye respuesta HTTP completa con headers disuasorios.
        Usa 403 Forbidden — el sistema ve al atacante pero no le deja pasar.
        """
        body = HTTP_BODY_DISUASORIO.format(session_id=session_id).encode("utf-8")

        headers = {k: v.format(session_id=session_id)
                   for k, v in HEADERS_DISUASORIOS.items()}
        headers["Content-Length"] = str(len(body))
        headers["Content-Type"]   = "text/html; charset=utf-8"
        headers["Connection"]     = "close"

        status_line  = f"HTTP/1.1 {status} Forbidden\r\n"
        header_block = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        response     = (status_line + header_block + "\r\n").encode("utf-8") + body
        return response

    def get_instance_signature(self) -> str:
        return f"AEGIS-{self._instance_sig}"


# ─────────────────────────────────────────────
# NIVEL 2 — SERVICIOS: Puertos señuelo con respuestas de detección
# ─────────────────────────────────────────────

class ServiceDecoyLayer:
    """
    Nivel 2 — Servicios.
    Abre puertos señuelo que parecen servicios reales.
    Cualquier conexión activa una respuesta que confirma detección.
    El atacante no sabe si es un servicio real o una trampa — ese es el objetivo.
    """

    # Puertos señuelo — rango 18000-19000, libre de servicios comunes.
    # Elegidos para no colisionar con SSH (22), HTTP (80/443),
    # servicios del SO, ni con los rangos AMTD (7100-9299).
    MAX_CONCURRENT_CONNECTIONS = 500

    DEFAULT_DECOY_PORTS = [
        18080,  # señuelo HTTP interno
        18443,  # señuelo HTTPS interno
        18222,  # señuelo SSH alternativo
        18090,  # señuelo admin / métricas
        18379,  # señuelo tipo Redis
        18017,  # señuelo tipo MongoDB
    ]

    def __init__(self, ports: Optional[list] = None):
        self.ports   = ports or self.DEFAULT_DECOY_PORTS
        self._servers: dict = {}   # port → asyncio.Server
        self._active = False
        self._connection_semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_CONNECTIONS)
        self._connections_dropped  = 0
        logger.info(f"[SHIELD.L2] Puertos señuelo configurados: {self.ports}")

    async def start(
        self,
        network_layer: NetworkSignatureLayer,
        on_probe: callable
    ):
        """
        Inicia todos los servidores señuelo en paralelo.
        on_probe: callback que recibe ProbeEvent cuando alguien conecta.
        """
        self._network_layer = network_layer
        self._on_probe      = on_probe
        self._active        = True

        tasks = []
        for port in self.ports:
            task = asyncio.create_task(
                self._start_decoy_server(port),
                name=f"shield.decoy.{port}"
            )
            tasks.append(task)

        logger.info(f"[SHIELD.L2] {len(self.ports)} servidores señuelo activos")
        return tasks

    async def _start_decoy_server(self, port: int):
        """Inicia un servidor señuelo en un puerto específico."""
        try:
            server = await asyncio.start_server(
                lambda r, w: self._handle_connection(r, w, port),
                host="0.0.0.0",
                port=port,
                reuse_address=True,
            )
            self._servers[port] = server
            logger.debug(f"[SHIELD.L2] Señuelo activo en puerto {port}")
            async with server:
                await server.serve_forever()
        except OSError as e:
            logger.warning(f"[SHIELD.L2] Puerto {port} no disponible: {e}")
        except asyncio.CancelledError:
            logger.debug(f"[SHIELD.L2] Señuelo puerto {port} detenido")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_port: int
    ):
        """
        Maneja una conexión entrante al puerto señuelo.
        Siempre responde con señal de detección activa.
        """
        if self._connection_semaphore.locked():
            self._connections_dropped += 1
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return
        async with self._connection_semaphore:
            await self._handle_connection_inner(reader, writer, target_port)

    async def _handle_connection_inner(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_port: int
    ):
        t_start    = time.monotonic()
        peer       = writer.get_extra_info("peername") or ("unknown", 0)
        source_ip  = peer[0]
        source_port= peer[1]
        session_id = secrets.token_hex(8).upper()

        logger.info(
            f"[SHIELD.L2] Contacto en puerto {target_port} "
            f"desde {source_ip}:{source_port} — sesión {session_id}"
        )

        # Leer primeros bytes para fingerprinting (max 512B, no bloqueante)
        raw_data = b""
        try:
            raw_data = await asyncio.wait_for(reader.read(512), timeout=2.0)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass

        # Determinar tipo de probe y respuesta apropiada
        probe_type, response = self._classify_and_respond(
            raw_data, target_port, session_id
        )

        # Enviar respuesta disuasoria
        try:
            writer.write(response)
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        duration_ms = (time.monotonic() - t_start) * 1000

        # Construir evento y notificar Nivel 3
        event = ProbeEvent(
            probe_id      = session_id,
            timestamp     = datetime.now(timezone.utc),
            source_ip     = source_ip,
            source_port   = source_port,
            target_port   = target_port,
            probe_type    = probe_type,
            threat_level  = self._assess_threat(target_port, raw_data),
            fingerprint   = self._fingerprint(source_ip, raw_data),
            raw_data      = raw_data[:64],   # solo primeros 64B en el registro
            response_sent = response[:80].decode("utf-8", errors="replace"),
            duration_ms   = duration_ms,
        )

        if self._on_probe:
            await self._on_probe(event)

    def _classify_and_respond(
        self,
        raw_data: bytes,
        port: int,
        session_id: str
    ) -> tuple:
        """
        Clasifica el tipo de probe por los datos recibidos
        y construye la respuesta apropiada.
        """
        data_str = raw_data.decode("utf-8", errors="ignore").upper()

        # Petición HTTP
        if any(m in data_str for m in ("GET ", "POST ", "HEAD ", "OPTIONS ")):
            response   = self._network_layer.build_http_response(session_id)
            probe_type = ProbeType.HTTP_REQUEST

        # Banner grab — conexión que espera sin enviar datos
        elif len(raw_data) == 0:
            response   = self._network_layer.build_tcp_banner(session_id)
            probe_type = ProbeType.BANNER_GRAB

        # Cualquier otro contacto TCP
        else:
            response   = self._network_layer.build_tcp_banner(session_id)
            probe_type = ProbeType.TCP_CONNECT

        return probe_type, response

    def _assess_threat(self, port: int, raw_data: bytes) -> ThreatLevel:
        """
        Evalúa el nivel de amenaza basado en el puerto y los datos.
        Puertos señuelo de BD (18379, 18017) = HIGH — objetivo directo.
        """
        high_value_ports = {18379, 18017, 18443, 18222, 6379, 27017, 5432, 3306, 1521}
        if port in high_value_ports:
            return ThreatLevel.HIGH
        if len(raw_data) > 100:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW

    def _fingerprint(self, source_ip: str, raw_data: bytes) -> str:
        """
        Genera fingerprint del explorador combinando IP y datos enviados.
        No reversible — solo para correlación interna.
        """
        payload = f"{source_ip}|{raw_data.hex()}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:16]

    async def stop(self):
        """Detiene todos los servidores señuelo."""
        self._active = False
        for port, server in self._servers.items():
            server.close()
            logger.debug(f"[SHIELD.L2] Señuelo detenido en puerto {port}")
        self._servers.clear()


# ─────────────────────────────────────────────
# NIVEL 3 — COMPORTAMIENTO: Registro y respuesta de detección
# ─────────────────────────────────────────────

class BehaviorTrackingLayer:
    """
    Nivel 3 — Comportamiento.
    Registra cada exploración del perímetro con contexto completo.
    Responde de forma que el explorador sabe que ha sido visto.
    Detecta patrones: mismo IP, ráfagas de puertos, reconocimiento sistemático.

    Este nivel es el que "habla" al atacante:
    No solo responde — responde de forma que comunica "te hemos visto".
    """

    def __init__(self):
        self._probes:    list  = []           # historial completo de eventos
        self._ip_counts: dict  = {}           # IP → lista de timestamps
        self._callbacks: list  = []           # listeners externos (Capa 3, Capa 7)
        self._total     = 0
        logger.info("[SHIELD.L3] Tracking de comportamiento activo")

    def register_callback(self, callback: callable):
        """
        Registra un callback externo que recibe cada ProbeEvent.
        Uso: Capa 3 (detección multi-agente) y Capa 7 (forense).
        """
        self._callbacks.append(callback)
        logger.debug(f"[SHIELD.L3] Callback registrado: {callback.__name__}")

    async def process(self, event: ProbeEvent):
        """
        Procesa un evento de probe:
        1. Registra en historial
        2. Actualiza contadores por IP
        3. Detecta patrones
        4. Notifica callbacks externos
        5. Eleva nivel de amenaza si hay patrón
        """
        self._probes.append(event)
        self._total += 1

        # Actualizar contador de IP
        ip = event.source_ip
        now = time.monotonic()
        if ip not in self._ip_counts:
            self._ip_counts[ip] = []
        self._ip_counts[ip].append(now)

        # Purgar entradas más antiguas de 1 hora
        cutoff = now - 3600
        self._ip_counts[ip] = [t for t in self._ip_counts[ip] if t > cutoff]

        # Detectar patrón y elevar amenaza si procede
        hits_last_hour = len(self._ip_counts[ip])
        if hits_last_hour >= 5:
            event = self._elevate(event, ThreatLevel.HIGH, hits_last_hour)
        elif hits_last_hour >= 2:
            event = self._elevate(event, ThreatLevel.MEDIUM, hits_last_hour)

        # Log con contexto completo
        self._log_event(event, hits_last_hour)

        # Notificar callbacks externos (Capa 3, Capa 7)
        for cb in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(event)
                else:
                    cb(event)
            except Exception as e:
                logger.warning(f"[SHIELD.L3] Error en callback {cb.__name__}: {e}")

    def _elevate(
        self,
        event: ProbeEvent,
        level: ThreatLevel,
        hits: int
    ) -> ProbeEvent:
        """Eleva el nivel de amenaza de un evento — retorna nuevo evento inmutable."""
        from dataclasses import replace
        logger.warning(
            f"[SHIELD.L3] PATRÓN DETECTADO — IP {event.source_ip} "
            f"ha contactado {hits}x en la última hora → {level.value}"
        )
        return replace(event, threat_level=level)

    def _log_event(self, event: ProbeEvent, hits: int):
        """Registro estructurado del evento para auditoría."""
        level = event.threat_level.value
        logger.info(
            f"[SHIELD.L3] [{level}] probe_id={event.probe_id} "
            f"ip={event.source_ip}:{event.source_port} "
            f"→ puerto={event.target_port} "
            f"tipo={event.probe_type.value} "
            f"fp={event.fingerprint} "
            f"hits_1h={hits} "
            f"dur={event.duration_ms:.1f}ms"
        )

    def get_probes_last_hour(self) -> list:
        """Retorna todos los eventos de la última hora."""
        cutoff = datetime.now(timezone.utc).timestamp() - 3600
        return [
            e for e in self._probes
            if e.timestamp.timestamp() > cutoff
        ]

    def get_ip_summary(self) -> dict:
        """Resumen de IPs que han contactado y su frecuencia."""
        return {
            ip: len(timestamps)
            for ip, timestamps in self._ip_counts.items()
            if timestamps
        }

    def export_log(self) -> list:
        """Exporta historial completo como lista de dicts — para Capa 7."""
        return [e.to_dict() for e in self._probes]


# ─────────────────────────────────────────────
# FACHADA PRINCIPAL — AegisShield
# ─────────────────────────────────────────────

class AegisShield:
    """
    Fachada de Capa 0.5 — Escudo Disuasorio.
    Orquesta los tres niveles simultáneamente.

    Uso:
        shield = AegisShield()
        shield.register_alert_callback(my_capa3_handler)
        await shield.start()
        ...
        await shield.stop()

    Consultas:
        shield.status()           → ShieldStatus actual
        shield.get_probe_log()    → historial exportable para Capa 7
        shield.get_ip_summary()   → IPs y frecuencia de contacto
    """

    def __init__(self, decoy_ports: Optional[list] = None):
        self.level1 = NetworkSignatureLayer()
        self.level2 = ServiceDecoyLayer(decoy_ports)
        self.level3 = BehaviorTrackingLayer()
        self._active      = False
        self._tasks: list = []
        self._started_at: Optional[datetime] = None

        logger.info(
            "[AEGIS.Shield] Capa 0.5 inicializada — "
            "3 niveles listos: red + servicios + comportamiento"
        )

    def register_alert_callback(self, callback: callable):
        """
        Registra callback externo para alertas de probe.
        Llamado por Capa 3 y Capa 7 para recibir eventos en tiempo real.

        callback recibe: ProbeEvent
        """
        self.level3.register_callback(callback)

    async def start(self):
        """
        Activa los tres niveles simultáneamente.
        Nivel 1 (firmas) → siempre activo en todas las respuestas.
        Nivel 2 (señuelos) → servidores asyncio en puertos configurados.
        Nivel 3 (comportamiento) → activo como receptor de eventos.
        """
        if self._active:
            logger.warning("[AEGIS.Shield] Ya estaba activo — ignorando start()")
            return

        self._active     = True
        self._started_at = datetime.now(timezone.utc)

        # Nivel 2 arranca con callback → Nivel 3
        decoy_tasks = await self.level2.start(
            network_layer=self.level1,
            on_probe=self.level3.process
        )
        self._tasks.extend(decoy_tasks)

        logger.info(
            f"[AEGIS.Shield] ✓ Escudo activo — "
            f"{len(self.level2.ports)} puertos señuelo | "
            f"firmas red activas | "
            f"tracking comportamiento activo"
        )

    async def stop(self):
        """Detiene todos los niveles ordenadamente."""
        if not self._active:
            return

        self._active = False
        await self.level2.stop()

        for task in self._tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
        self._tasks.clear()

        logger.info("[AEGIS.Shield] Escudo disuasorio detenido")

    def status(self) -> ShieldStatus:
        """Estado actual del escudo."""
        probes_1h = self.level3.get_probes_last_hour()
        last_probe = probes_1h[-1].timestamp if probes_1h else None
        return ShieldStatus(
            active          = self._active,
            level1_active   = self._active,
            level2_active   = self._active,
            level3_active   = self._active,
            ports_monitored = self.level2.ports,
            total_probes    = self.level3._total,
            probes_last_hour= len(probes_1h),
            last_probe_at   = last_probe,
            started_at      = self._started_at or datetime.now(timezone.utc),
        )

    def get_probe_log(self) -> list:
        """Exporta historial completo — para Capa 7 (forense)."""
        return self.level3.export_log()

    def get_ip_summary(self) -> dict:
        """IPs que han contactado y frecuencia — para Capa 3 (detección)."""
        return self.level3.get_ip_summary()

    def build_tcp_banner(self, session_id: Optional[str] = None) -> bytes:
        """
        Construye banner TCP disuasorio.
        Uso externo: otros módulos pueden emitir el banner sin pasar por el señuelo.
        """
        sid = session_id or secrets.token_hex(8).upper()
        return self.level1.build_tcp_banner(sid)

    def build_http_response(self, session_id: Optional[str] = None) -> bytes:
        """
        Construye respuesta HTTP disuasoria.
        Uso externo: API gateway u otros módulos pueden usarla directamente.
        """
        sid = session_id or secrets.token_hex(8).upper()
        return self.level1.build_http_response(sid)
