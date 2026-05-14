"""
AEGIS — Capa 3: Detección Multi-Agente
========================================
Detección 100% por comportamiento — nunca por firma.

DOS MECANISMOS SIMULTÁNEOS:
    Pasivo  — monitoriza contactos con señuelos de Capa 2 (campo de minas)
    Activo  — analiza patrones de reconocimiento y exploración en tiempo real

DETECCIÓN DE ATAQUE COORDINADO:
    Un solo actor explorando múltiples capas simultáneamente.
    Múltiples IPs con patrones sincronizados → coordinación.
    Velocidad de exploración anormal → automatización.

UMBRAL INVARIABLE:
    Detección < 1 segundo desde el primer indicador.

SALIDAS:
    → Capa 1 (twin): dispara salto atómico si se confirma intrusión
    → Capa 4 (lockdown): solicita cierre atómico
    → Capa 7 (forensics): entrega evidencia completa
"""

import asyncio
import hashlib
import logging
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("aegis.detector")

_MAX_PROFILES   = 5000   # máximo de IPs en memoria
_PROFILE_TTL_S  = 3600   # TTL de perfil inactivo (1 hora)
_EVICT_RATIO    = 0.2    # porcentaje a evictar cuando se llena


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class DetectionType(str, Enum):
    MINE_CONTACT      = "MINE_CONTACT"       # pasivo: contacto con señuelo
    RECON_PATTERN     = "RECON_PATTERN"      # activo: patrón de reconocimiento
    EXPLORATION       = "EXPLORATION"        # activo: exploración sistemática
    COORDINATED       = "COORDINATED"        # múltiples vectores simultáneos
    AUTOMATED         = "AUTOMATED"          # velocidad anormal → bot/script


class ThreatConfidence(str, Enum):
    CONFIRMED  = "CONFIRMED"    # certeza total — señuelo tocado
    HIGH       = "HIGH"         # patrón claro de ataque
    MEDIUM     = "MEDIUM"       # comportamiento sospechoso
    LOW        = "LOW"          # anomalía leve


# ─────────────────────────────────────────────
# EVENTO DE DETECCIÓN
# ─────────────────────────────────────────────

@dataclass
class DetectionEvent:
    """Evento de detección generado por el sistema multi-agente."""
    detection_id:   str
    timestamp:      datetime
    detection_type: DetectionType
    confidence:     ThreatConfidence
    source_ips:     list            # una o más IPs involucradas
    indicators:     list            # lista de indicadores que dispararon la detección
    evidence:       dict            # evidencia completa para Capa 7
    action_required:str             # "JUMP" | "LOCKDOWN" | "ALERT" | "MONITOR"
    elapsed_ms:     float           # tiempo desde primer indicador hasta detección

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"]       = self.timestamp.isoformat()
        d["detection_type"]  = self.detection_type.value
        d["confidence"]      = self.confidence.value
        return d


# ─────────────────────────────────────────────
# PERFIL DE IP — acumula comportamiento por IP
# ─────────────────────────────────────────────

@dataclass
class IPProfile:
    """Perfil de comportamiento acumulado para una IP."""
    ip:               str
    first_seen:       float          # monotonic timestamp
    last_seen:        float
    mine_contacts:    list           # contactos con señuelos
    probe_events:     list           # eventos del escudo (Capa 0.5)
    paths_touched:    set            # rutas/recursos explorados
    ports_touched:    set            # puertos contactados
    request_times:    deque          # timestamps de peticiones (ventana 60s)
    total_events:     int = 0

    def __post_init__(self):
        if not isinstance(self.request_times, deque):
            self.request_times = deque(maxlen=500)
        if not isinstance(self.paths_touched, set):
            self.paths_touched = set(self.paths_touched)
        if not isinstance(self.ports_touched, set):
            self.ports_touched = set(self.ports_touched)

    def add_event(self, event_type: str, detail: str, port: int = 0):
        now = time.monotonic()
        self.last_seen = now
        self.request_times.append(now)
        self.total_events += 1
        if detail:
            self.paths_touched.add(detail)
        if port:
            self.ports_touched.add(port)

    def requests_per_second(self, window: float = 10.0) -> float:
        """Peticiones por segundo en la ventana de tiempo especificada."""
        now    = time.monotonic()
        cutoff = now - window
        recent = sum(1 for t in self.request_times if t > cutoff)
        elapsed = min(window, now - self.first_seen)
        return recent / elapsed if elapsed > 0 else 0.0

    def unique_paths(self) -> int:
        return len(self.paths_touched)

    def unique_ports(self) -> int:
        return len(self.ports_touched)

    def time_active_seconds(self) -> float:
        return self.last_seen - self.first_seen


# ─────────────────────────────────────────────
# AGENTE PASIVO — monitoriza señuelos de Capa 2
# ─────────────────────────────────────────────

class PassiveAgent:
    """
    Agente pasivo — receptor de eventos de Capa 2 (campo de minas).
    Cualquier contacto con un señuelo es detección CONFIRMADA inmediata.
    Sin análisis adicional necesario — un legítimo jamás toca un señuelo.
    """

    def __init__(self, on_detection: Callable):
        self._on_detection = on_detection
        self._contacts:    list  = []
        self._contact_times: dict = defaultdict(list)  # ip → [timestamps]

    async def on_mine_contact(self, contact) -> Optional[DetectionEvent]:
        """
        Recibe un MineContact de Capa 2.
        Genera detección CONFIRMADA inmediatamente — umbral < 1s garantizado.
        """
        t0  = time.monotonic()
        ip  = contact.source_ip

        self._contacts.append(contact)
        self._contact_times[ip].append(t0)

        # Detección CONFIRMADA — señuelo tocado = intruso detectado
        detection = DetectionEvent(
            detection_id   = secrets.token_hex(6).upper(),
            timestamp      = datetime.now(timezone.utc),
            detection_type = DetectionType.MINE_CONTACT,
            confidence     = ThreatConfidence.CONFIRMED,
            source_ips     = [ip],
            indicators     = [
                f"Señuelo tocado: {contact.mine_type.value} '{contact.mine_name}'",
                f"Severidad del señuelo: {contact.severity}",
                f"Método: {contact.method}",
            ],
            evidence       = {
                "contact_id":   contact.contact_id,
                "mine_id":      contact.mine_id,
                "mine_type":    contact.mine_type,
                "severity":     contact.severity,
                "fingerprint":  contact.fingerprint,
                "payload_hex":  contact.payload.hex(),
            },
            action_required = "JUMP",   # señuelo tocado → salto inmediato
            elapsed_ms      = (time.monotonic() - t0) * 1000,
        )

        logger.warning(
            f"[DETECT.PASIVO] ⚡ DETECCIÓN CONFIRMADA — "
            f"id={detection.detection_id} "
            f"ip={ip} señuelo='{contact.mine_name}' "
            f"elapsed={detection.elapsed_ms:.2f}ms"
        )

        await self._on_detection(detection)
        return detection

    def contacts_from_ip(self, ip: str) -> list:
        return [c for c in self._contacts if c.source_ip == ip]

    def total_contacts(self) -> int:
        return len(self._contacts)


# ─────────────────────────────────────────────
# AGENTE ACTIVO — analiza patrones de comportamiento
# ─────────────────────────────────────────────

class ActiveAgent:
    """
    Agente activo — analiza patrones de reconocimiento y exploración.
    Detecta comportamiento anómalo sin necesidad de que toque un señuelo.

    PATRONES QUE DETECTA:
        Reconocimiento  — exploración sistemática de rutas/puertos
        Automatización  — velocidad de peticiones imposible para humano
        Coordinación    — múltiples IPs con patrones sincronizados
    """

    # Umbrales de comportamiento — todos basados en observación, no en firmas
    RECON_PATHS_THRESHOLD     = 3      # ≥3 rutas distintas en 30s → reconocimiento
    EXPLORATION_PORTS_THRESHOLD = 3    # ≥3 puertos distintos → exploración
    AUTOMATION_RPS_THRESHOLD  = 5.0    # ≥5 req/s → automatización (imposible humano)
    COORDINATION_SYNC_WINDOW  = 2.0    # IPs sincronizadas en ventana de 2s
    COORDINATION_MIN_IPS      = 2      # mínimo 2 IPs para considerar coordinación

    def __init__(self, on_detection: Callable):
        self._on_detection  = on_detection
        self._profiles:     dict  = {}   # ip → IPProfile
        self._detections:   list  = []
        self._event_times:  deque = deque(maxlen=1000)  # (timestamp, ip) globales

    def _get_profile(self, ip: str) -> IPProfile:
        if len(self._profiles) >= _MAX_PROFILES and ip not in self._profiles:
            self._evict_old_profiles()
        if ip not in self._profiles:
            now = time.monotonic()
            self._profiles[ip] = IPProfile(
                ip             = ip,
                first_seen     = now,
                last_seen      = now,
                mine_contacts  = [],
                probe_events   = [],
                paths_touched  = set(),
                ports_touched  = set(),
                request_times  = deque(maxlen=500),
            )
        return self._profiles[ip]

    async def register_event(
        self,
        ip: str,
        port: int,
        path: str,
        source: str = "shield"   # "shield" | "mine" | "network"
    ) -> Optional[DetectionEvent]:
        """
        Registra un evento de comportamiento y evalúa si hay patrón anómalo.
        Retorna DetectionEvent si se detecta algo, None si todo normal.
        """
        t0      = time.monotonic()
        profile = self._get_profile(ip)
        profile.add_event(source, path, port)
        self._event_times.append((t0, ip))

        # Evaluar patrones en orden de severidad
        detection = (
            await self._check_automation(profile, t0)      or
            await self._check_recon(profile, t0)           or
            await self._check_exploration(profile, t0)     or
            await self._check_coordination(ip, t0)
        )

        return detection

    async def _check_recon(
        self, profile: IPProfile, t0: float
    ) -> Optional[DetectionEvent]:
        """Reconocimiento: exploración sistemática de múltiples rutas."""
        if profile.unique_paths() < self.RECON_PATHS_THRESHOLD:
            return None
        if profile.time_active_seconds() > 30:
            return None   # demasiado lento para ser reconocimiento activo

        detection = DetectionEvent(
            detection_id   = secrets.token_hex(6).upper(),
            timestamp      = datetime.now(timezone.utc),
            detection_type = DetectionType.RECON_PATTERN,
            confidence     = ThreatConfidence.HIGH,
            source_ips     = [profile.ip],
            indicators     = [
                f"{profile.unique_paths()} rutas distintas exploradas en {profile.time_active_seconds():.1f}s",
                f"Rutas: {list(profile.paths_touched)[:5]}",
                f"Total eventos: {profile.total_events}",
            ],
            evidence       = {
                "paths_touched":     list(profile.paths_touched),
                "time_active_s":     profile.time_active_seconds(),
                "total_events":      profile.total_events,
            },
            action_required = "LOCKDOWN",
            elapsed_ms      = (time.monotonic() - t0) * 1000,
        )
        await self._emit(detection)
        return detection

    async def _check_exploration(
        self, profile: IPProfile, t0: float
    ) -> Optional[DetectionEvent]:
        """Exploración: múltiples puertos distintos contactados."""
        if profile.unique_ports() < self.EXPLORATION_PORTS_THRESHOLD:
            return None

        detection = DetectionEvent(
            detection_id   = secrets.token_hex(6).upper(),
            timestamp      = datetime.now(timezone.utc),
            detection_type = DetectionType.EXPLORATION,
            confidence     = ThreatConfidence.HIGH,
            source_ips     = [profile.ip],
            indicators     = [
                f"{profile.unique_ports()} puertos distintos explorados",
                f"Puertos: {sorted(profile.ports_touched)}",
                f"Tiempo activo: {profile.time_active_seconds():.1f}s",
            ],
            evidence       = {
                "ports_touched":  sorted(profile.ports_touched),
                "time_active_s":  profile.time_active_seconds(),
                "total_events":   profile.total_events,
            },
            action_required = "LOCKDOWN",
            elapsed_ms      = (time.monotonic() - t0) * 1000,
        )
        await self._emit(detection)
        return detection

    async def _check_automation(
        self, profile: IPProfile, t0: float
    ) -> Optional[DetectionEvent]:
        """Automatización: velocidad de peticiones imposible para un humano."""
        rps = profile.requests_per_second(window=5.0)
        if rps < self.AUTOMATION_RPS_THRESHOLD:
            return None

        detection = DetectionEvent(
            detection_id   = secrets.token_hex(6).upper(),
            timestamp      = datetime.now(timezone.utc),
            detection_type = DetectionType.AUTOMATED,
            confidence     = ThreatConfidence.HIGH,
            source_ips     = [profile.ip],
            indicators     = [
                f"Velocidad: {rps:.1f} req/s — umbral humano superado ({self.AUTOMATION_RPS_THRESHOLD} req/s)",
                f"Total eventos en ventana: {profile.total_events}",
            ],
            evidence       = {
                "requests_per_second": rps,
                "threshold":           self.AUTOMATION_RPS_THRESHOLD,
                "total_events":        profile.total_events,
            },
            action_required = "LOCKDOWN",
            elapsed_ms      = (time.monotonic() - t0) * 1000,
        )
        await self._emit(detection)
        return detection

    async def _check_coordination(
        self, current_ip: str, t0: float
    ) -> Optional[DetectionEvent]:
        """
        Coordinación: múltiples IPs distintas activas en la misma ventana temporal.
        Sugiere ataque distribuido coordinado.
        """
        window  = self.COORDINATION_SYNC_WINDOW
        cutoff  = t0 - window
        # IPs distintas activas en la ventana
        active_ips = set(
            ip for ts, ip in self._event_times
            if ts > cutoff and ip != current_ip
        )
        active_ips.add(current_ip)

        if len(active_ips) < self.COORDINATION_MIN_IPS:
            return None

        # Solo generar detección si hay al menos 2 IPs distintas con múltiples eventos
        multi_event_ips = [
            ip for ip in active_ips
            if ip in self._profiles and self._profiles[ip].total_events >= 2
        ]
        if len(multi_event_ips) < self.COORDINATION_MIN_IPS:
            return None

        detection = DetectionEvent(
            detection_id   = secrets.token_hex(6).upper(),
            timestamp      = datetime.now(timezone.utc),
            detection_type = DetectionType.COORDINATED,
            confidence     = ThreatConfidence.HIGH,
            source_ips     = list(active_ips),
            indicators     = [
                f"{len(active_ips)} IPs distintas activas en ventana de {window}s",
                f"IPs: {list(active_ips)}",
                f"Patrón: ataque distribuido coordinado",
            ],
            evidence       = {
                "active_ips":    list(active_ips),
                "window_s":      window,
                "profiles":      {
                    ip: {
                        "total_events": self._profiles[ip].total_events,
                        "paths":        list(self._profiles[ip].paths_touched)[:3],
                    }
                    for ip in active_ips if ip in self._profiles
                },
            },
            action_required = "JUMP",
            elapsed_ms      = (time.monotonic() - t0) * 1000,
        )
        await self._emit(detection)
        return detection

    async def _emit(self, detection: DetectionEvent):
        self._detections.append(detection)
        logger.warning(
            f"[DETECT.ACTIVO] ⚡ {detection.detection_type.value} — "
            f"id={detection.detection_id} "
            f"confianza={detection.confidence.value} "
            f"ips={detection.source_ips} "
            f"acción={detection.action_required} "
            f"elapsed={detection.elapsed_ms:.2f}ms"
        )
        await self._on_detection(detection)

    def _evict_old_profiles(self):
        """Elimina los perfiles más viejos cuando se supera _MAX_PROFILES.
        También limpia perfiles con TTL expirado.
        """
        now = time.monotonic()
        # 1. Eliminar perfiles con TTL expirado
        expired = [
            ip for ip, p in self._profiles.items()
            if now - p.last_seen > _PROFILE_TTL_S
        ]
        for ip in expired:
            del self._profiles[ip]
        if expired:
            logger.debug(f"[DETECTOR] Evictados {len(expired)} perfiles TTL expirado")

        # 2. Si sigue lleno, evictar los más viejos por last_seen
        if len(self._profiles) >= _MAX_PROFILES:
            n_evict = max(1, int(_MAX_PROFILES * _EVICT_RATIO))
            oldest  = sorted(self._profiles.items(),
                             key=lambda x: x[1].last_seen)[:n_evict]
            for ip, _ in oldest:
                del self._profiles[ip]
            logger.warning(
                f"[DETECTOR] Evictados {n_evict} perfiles más viejos — "
                f"perfiles activos={len(self._profiles)}"
            )

    def get_profile(self, ip: str) -> Optional[IPProfile]:
        return self._profiles.get(ip)

    def total_detections(self) -> int:
        return len(self._detections)

    def active_ips(self) -> list:
        return list(self._profiles.keys())


# ─────────────────────────────────────────────
# FACHADA PRINCIPAL — AegisDetector
# ─────────────────────────────────────────────

class AegisDetector:
    """
    Fachada de Capa 3 — Detección Multi-Agente.
    Orquesta agente pasivo y activo simultáneamente.

    INTEGRACIÓN CON OTRAS CAPAS:
        Capa 0.5 (shield)  → register_shield_probe()
        Capa 2 (minefield) → register_mine_contact()  [callback directo]
        Capa 1 (twin)      → callback on_jump_required
        Capa 4 (lockdown)  → callback on_lockdown_required
        Capa 7 (forensics) → callback on_forensic_evidence

    Uso:
        detector = AegisDetector()
        detector.register_jump_callback(twin_chain.trigger_jump)
        detector.register_lockdown_callback(lockdown.execute)
        detector.register_forensic_callback(forensics.ingest)

        # Conectar a Capa 2:
        minefield.register_detection_callback(detector.on_mine_contact)

        # Registrar eventos de Capa 0.5:
        detector.register_shield_probe(probe_event)
    """

    def __init__(self):
        self._passive = PassiveAgent(on_detection=self._handle_detection)
        self._active  = ActiveAgent(on_detection=self._handle_detection)

        self._detections:          list  = []
        self._callbacks_jump:      list  = []   # → Capa 1
        self._callbacks_lockdown:  list  = []   # → Capa 4
        self._callbacks_forensic:  list  = []   # → Capa 7

        # Deduplicación — evitar cascada de detecciones por el mismo evento
        self._recent_detection_ips: dict  = {}   # ip → last_detection_time
        self._DEDUP_WINDOW = 5.0   # segundos — una detección por IP cada 5s máximo

        self._event_semaphore = asyncio.Semaphore(500)
        self._total_events_discarded = 0

        logger.info(
            "[AEGIS.Detector] Capa 3 inicializada — "
            "agente pasivo (minas) + agente activo (patrones) activos"
        )

    # ── Registro de callbacks hacia otras capas ───────────────────────────────

    def register_jump_callback(self, cb: Callable):
        """Capa 1 — se llama cuando se confirma intrusión → salto atómico."""
        self._callbacks_jump.append(cb)

    def register_lockdown_callback(self, cb: Callable):
        """Capa 4 — se llama cuando se detecta amenaza → cierre atómico."""
        self._callbacks_lockdown.append(cb)

    def register_forensic_callback(self, cb: Callable):
        """Capa 7 — recibe evidencia completa de cada detección."""
        self._callbacks_forensic.append(cb)

    # ── Puntos de entrada desde otras capas ──────────────────────────────────

    async def on_mine_contact(self, contact):
        """
        Callback para Capa 2 (minefield).
        Contacto con señuelo → detección CONFIRMADA inmediata.
        El agente activo registra el evento para correlación de patrones
        pero SIN generar detección propia — el pasivo ya la emitió.
        """
        # Agente pasivo: detección CONFIRMED inmediata
        await self._passive.on_mine_contact(contact)

        # Agente activo: solo acumular en perfil, sin evaluar patrones
        # Evita doble detección — CONFIRMED tiene prioridad y es suficiente
        profile = self._active._get_profile(contact.source_ip)
        profile.add_event("mine", contact.mine_name, contact.source_port)

    async def register_shield_probe(self, probe_event):
        if self._event_semaphore.locked():
            self._total_events_discarded += 1
            return
        async with self._event_semaphore:
            await self._active.register_event(
                ip=probe_event.source_ip,
                port=probe_event.target_port,
                path=str(probe_event.target_port),
                source="shield"
            )

    async def register_network_event(self, ip: str, port: int, path: str = ""):
        if self._event_semaphore.locked():
            self._total_events_discarded += 1
            return
        async with self._event_semaphore:
            await self._active.register_event(ip=ip, port=port, path=path)

    # ── Dispatcher interno ────────────────────────────────────────────────────

    async def _handle_detection(self, detection: DetectionEvent):
        """
        Recibe detección de cualquier agente y la despacha a las capas correctas.
        Deduplicación por tipo:
          - CONFIRMED (señuelo tocado): ventana corta 0.1s — casi nunca duplica
          - Resto: ventana normal 5s — evita cascadas de patrones
        """
        now    = time.monotonic()
        window = 0.1 if detection.confidence == ThreatConfidence.CONFIRMED else self._DEDUP_WINDOW
        for ip in detection.source_ips:
            last = self._recent_detection_ips.get((ip, detection.confidence), 0)
            if now - last < window:
                logger.debug(f"[DETECT] Deduplicando {detection.confidence} para IP {ip}")
                return
        for ip in detection.source_ips:
            self._recent_detection_ips[(ip, detection.confidence)] = now

        self._detections.append(detection)

        # Despachar según acción requerida
        if detection.action_required == "JUMP":
            await self._dispatch_jump(detection)
        elif detection.action_required == "LOCKDOWN":
            await self._dispatch_lockdown(detection)

        # Siempre enviar a forense
        await self._dispatch_forensic(detection)

    async def _dispatch_jump(self, detection: DetectionEvent):
        """Dispara salto atómico en Capa 1."""
        for cb in self._callbacks_jump:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(detection)
                else:
                    cb(detection)
            except Exception as e:
                logger.error(f"[DETECT] Error en callback de salto: {e}")

    async def _dispatch_lockdown(self, detection: DetectionEvent):
        """Solicita cierre atómico a Capa 4."""
        for cb in self._callbacks_lockdown:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(detection)
                else:
                    cb(detection)
            except Exception as e:
                logger.error(f"[DETECT] Error en callback de lockdown: {e}")

    async def _dispatch_forensic(self, detection: DetectionEvent):
        """Entrega evidencia a Capa 7."""
        for cb in self._callbacks_forensic:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(detection)
                else:
                    cb(detection)
            except Exception as e:
                logger.error(f"[DETECT] Error en callback forense: {e}")

    # ── Consultas ─────────────────────────────────────────────────────────────

    def total_detections(self) -> int:
        return len(self._detections)

    def get_detection_log(self) -> list:
        """Historial completo de detecciones — para Capa 7."""
        return [d.to_dict() for d in self._detections]

    def get_profile(self, ip: str) -> Optional[IPProfile]:
        """Perfil de comportamiento de una IP específica."""
        return self._active.get_profile(ip)

    def active_ips(self) -> list:
        return self._active.active_ips()

    def get_rate_limit_stats(self) -> dict:
        return {
            "semaphore_limit":        self._event_semaphore._value,
            "events_discarded":       self._total_events_discarded,
            "currently_processing":   500 - self._event_semaphore._value,
        }

    def status(self) -> dict:
        return {
            "total_detections":  self.total_detections(),
            "passive_contacts":  self._passive.total_contacts(),
            "active_detections": self._active.total_detections(),
            "active_ips":        len(self.active_ips()),
            "callbacks_jump":    len(self._callbacks_jump),
            "callbacks_lockdown":len(self._callbacks_lockdown),
            "callbacks_forensic":len(self._callbacks_forensic),
            "rate_limit":        self.get_rate_limit_stats(),
        }
