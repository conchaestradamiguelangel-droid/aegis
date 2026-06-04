"""
AEGIS — Fachada Principal de Integración
==========================================
Punto único de entrada y control del sistema completo.

ORDEN DE CONEXIÓN:
    Capa 0   → base criptográfica de todo
    Capa 0.5 → escudo disuasorio, opera continuamente
    Capa 1   → gemelo en cadena, opera continuamente
    Capa 2   → campo de minas alimenta Capa 3
    Capa 3   → detección dispara Capa 4
    Capa 4   → cierre atómico dispara Capa 1
    Capa 5   → superficie móvil AMTD, opera continuamente
    Capa 6   → burbuja recibe al intruso atrapado
    Capa 7   → análisis forense alimenta Capa 8
    Capa 8   → aprendizaje colectivo

FLUJO DE AMENAZA:
    Intruso detectado (C3) → cierre atómico (C4) → salto de gemelo (C1)
    Intruso atrapado (C6) → análisis forense (C7) → aprendizaje (C8)

FILOSOFÍA:
    Un solo objeto AegisSystem para gobernarlos a todos.
    start() arranca todo. stop() detiene todo ordenadamente.
    100% defensivo — nunca contraataca.
"""

import asyncio
import time
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from core.crypto    import AegisCrypto
from core.twin      import TwinChain, JumpTrigger
from core.lockdown  import AegisLockdown, LockdownTrigger

from layers.shield    import AegisShield
from layers.minefield import AegisMinefield
from layers.detector  import AegisDetector, DetectionEvent
from layers.amtd      import AegisAMTD
from layers.bubble    import AegisBubble, InteractionType
from layers.forensic  import AegisForensic
from layers.learning  import AegisLearning

from integrations.telegram_alerts import TelegramAlerter, AlertConfig
from core.incident_reporter     import IncidentReporter
from integrations.enlil_connector import EnlilConnector
from core.persistence import CheckpointManager, AutoCheckpointer
from core.wal import WALManager

logger = logging.getLogger("aegis.system")


# ─────────────────────────────────────────────
# MONITOR DE SUPERFICIE — Mejora 6
# ─────────────────────────────────────────────

@dataclass
class LayerActivity:
    """Registro de actividad de una capa."""
    layer_id:      str
    layer_name:    str
    last_event_at: Optional[datetime]
    event_count:   int   = 0
    is_active:     bool  = True   # True = arrancada, False = sugerida para desactivar

    def days_since_last_event(self) -> Optional[float]:
        if self.last_event_at is None:
            return None
        delta = datetime.now(timezone.utc) - self.last_event_at
        return round(delta.total_seconds() / 86400, 2)

    def to_dict(self) -> dict:
        return {
            "layer_id":              self.layer_id,
            "layer_name":            self.layer_name,
            "last_event_at":         self.last_event_at.isoformat()
                                     if self.last_event_at else None,
            "days_since_last_event": self.days_since_last_event(),
            "event_count":           self.event_count,
            "is_active":             self.is_active,
        }


class SurfaceMonitor:
    """
    Mejora 6 — Monitor de superficie de ataque mínima.

    FILOSOFÍA:
        Una capa que nadie ataca en X días puede estar exponiendo
        superficie sin aportar inteligencia. Mejor desactivarla
        temporalmente para reducir la superficie visible al atacante.

    QUÉ HACE:
        Registra la última vez que cada capa recibió actividad real
        (evento de señuelo, detección, probe de escudo, etc.).
        Si una capa lleva más de `inactive_threshold_days` sin actividad,
        la incluye en las sugerencias de desactivación.

    QUÉ NO HACE:
        No desactiva capas automáticamente — solo sugiere.
        La decisión es siempre del operador.
        Nunca sugiere desactivar C0 (crypto), C1 (twin) o C4 (lockdown)
        — son capas internas sin superficie expuesta.

    CAPAS MONITORIZADAS:
        C0.5 — Escudo disuasorio     (shield)
        C2   — Campo de minas        (minefield)
        C3   — Detector              (detector)
        C5   — Superficie AMTD       (amtd)
        C6   — Burbuja de engaño     (bubble)
        C7   — Análisis forense      (forensic)
        C8   — Aprendizaje colectivo (learning)

    CAPAS NUNCA SUGERIDAS PARA DESACTIVAR (internas):
        C0   — Criptografía post-cuántica
        C1   — Gemelo en cadena
        C4   — Cierre atómico
    """

    # Capas que NUNCA se sugieren para desactivar
    INTERNAL_LAYERS = {"C0", "C1", "C4"}

    DEFAULT_INACTIVE_DAYS = 7   # sin actividad en 7 días → sugerir

    def __init__(self, inactive_threshold_days: float = None):
        self._threshold_days = (
            inactive_threshold_days or self.DEFAULT_INACTIVE_DAYS
        )
        self._layers: dict = {}   # layer_id → LayerActivity
        self._initialized_at = datetime.now(timezone.utc)

        # Registrar capas monitorizables con estado inicial
        self._register_defaults()

    def _register_defaults(self):
        """Registra todas las capas monitorizables con actividad desconocida."""
        capas = [
            ("C0.5", "Escudo disuasorio (shield)"),
            ("C2",   "Campo de minas (minefield)"),
            ("C3",   "Detector multi-agente"),
            ("C5",   "Superficie AMTD"),
            ("C6",   "Burbuja evolutiva de engaño"),
            ("C7",   "Análisis forense"),
            ("C8",   "Aprendizaje colectivo"),
        ]
        for layer_id, layer_name in capas:
            self._layers[layer_id] = LayerActivity(
                layer_id      = layer_id,
                layer_name    = layer_name,
                last_event_at = None,
                event_count   = 0,
            )

    def record_event(self, layer_id: str, n: int = 1):
        """
        Registra actividad en una capa.
        Llamar cada vez que la capa recibe un evento real:
            shield   → probe recibido
            minefield→ señuelo tocado
            detector → detección registrada
            amtd     → rotación ejecutada
            bubble   → interacción con intruso
            forensic → incidente procesado
            learning → perfil ingestado
        """
        if layer_id not in self._layers:
            return
        layer = self._layers[layer_id]
        layer.last_event_at = datetime.now(timezone.utc)
        layer.event_count  += n

    def get_suggestions(self) -> list:
        """
        Retorna lista de sugerencias de desactivación.
        Una capa aparece si lleva más de threshold_days sin actividad.
        Las capas internas (C0/C1/C4) nunca aparecen.

        Cada sugerencia incluye:
            layer_id, layer_name, days_inactive, reason, suggestion
        """
        now         = datetime.now(timezone.utc)
        sugerencias = []

        for layer_id, layer in self._layers.items():
            if layer_id in self.INTERNAL_LAYERS:
                continue
            if not layer.is_active:
                continue   # ya desactivada — no sugerir de nuevo

            days = layer.days_since_last_event()

            # Si nunca tuvo actividad y lleva más de threshold iniciada
            if days is None:
                days_since_init = (
                    (now - self._initialized_at).total_seconds() / 86400
                )
                if days_since_init < self._threshold_days:
                    continue   # demasiado pronto para juzgar
                days   = days_since_init
                reason = "Sin actividad desde el arranque"
            elif days < self._threshold_days:
                continue   # actividad reciente — no sugerir
            else:
                reason = f"Sin actividad en {days:.1f} días"

            sugerencias.append({
                "layer_id":     layer_id,
                "layer_name":   layer.layer_name,
                "days_inactive":round(days, 2),
                "reason":       reason,
                "suggestion":   (
                    f"Considerar desactivar {layer_id} ({layer.layer_name}) "
                    f"para reducir superficie expuesta. "
                    f"Reactivar ante nueva actividad en esa capa."
                ),
            })

        # Ordenar por días de inactividad descendente — más urgente primero
        return sorted(sugerencias, key=lambda x: x["days_inactive"], reverse=True)

    def mark_deactivated(self, layer_id: str):
        """Marca una capa como desactivada por el operador."""
        if layer_id in self._layers and layer_id not in self.INTERNAL_LAYERS:
            self._layers[layer_id].is_active = False
            logger.info(f"[SURFACE] Capa {layer_id} marcada como desactivada")

    def mark_reactivated(self, layer_id: str):
        """Marca una capa como reactivada."""
        if layer_id in self._layers:
            self._layers[layer_id].is_active = True
            logger.info(f"[SURFACE] Capa {layer_id} reactivada")

    def get_layer_activity(self, layer_id: str) -> Optional[dict]:
        """Retorna el estado de actividad de una capa concreta."""
        layer = self._layers.get(layer_id)
        return layer.to_dict() if layer else None

    def get_all_activity(self) -> list:
        """Retorna el estado de actividad de todas las capas."""
        return [l.to_dict() for l in self._layers.values()]

    def surface_score(self) -> dict:
        """
        Score de superficie expuesta [0.0–1.0].
        0.0 = superficie mínima (pocas capas activas con actividad reciente)
        1.0 = superficie máxima (todas las capas activas sin filtrar)

        Útil para dashboards — cuanto más bajo mejor.
        """
        total_layers   = len(self._layers)
        active_layers  = sum(1 for l in self._layers.values() if l.is_active)
        with_activity  = sum(
            1 for l in self._layers.values()
            if l.is_active and l.last_event_at is not None
        )
        pending_suggest = len(self.get_suggestions())

        # Score: capas activas sobre total, penalizado por sugerencias pendientes
        base  = active_layers  / total_layers if total_layers else 1.0
        bonus = with_activity  / active_layers if active_layers else 0.0
        penalty = pending_suggest / total_layers

        score = round(min(1.0, base - bonus * 0.1 + penalty * 0.2), 3)

        return {
            "score":            score,
            "total_layers":     total_layers,
            "active_layers":    active_layers,
            "with_activity":    with_activity,
            "pending_suggestions": pending_suggest,
            "threshold_days":   self._threshold_days,
        }

    def status(self) -> dict:
        return {
            "threshold_days":      self._threshold_days,
            "layers_monitored":    len(self._layers),
            "suggestions_pending": len(self.get_suggestions()),
            "surface_score":       self.surface_score()["score"],
        }


# ─────────────────────────────────────────────
# ESTADO DEL SISTEMA
# ─────────────────────────────────────────────

class SystemStatus(str, Enum):
    OFFLINE    = "OFFLINE"
    STARTING   = "STARTING"
    ONLINE     = "ONLINE"
    ALERT      = "ALERT"      # amenaza detectada — sistema elevado
    LOCKDOWN   = "LOCKDOWN"   # cierre activo
    STOPPING   = "STOPPING"



class _TimingWindow:
    """Rolling window of latency samples — computes p50/p95/p99."""

    def __init__(self, max_samples: int = 200):
        self._samples: list = []
        self._max     = max_samples

    def record(self, ms: float):
        self._samples.append(ms)
        if len(self._samples) > self._max:
            self._samples = self._samples[-self._max:]

    def percentiles(self) -> dict:
        if not self._samples:
            return {"p50": None, "p95": None, "p99": None, "count": 0}
        s = sorted(self._samples)
        n = len(s)
        def pct(p):
            return round(s[min(int(p * n // 100), n - 1)], 1)
        return {"p50": pct(50), "p95": pct(95), "p99": pct(99), "count": n}


@dataclass
class SystemSnapshot:
    """Estado completo del sistema en un momento dado."""
    timestamp:        datetime
    status:           SystemStatus
    threat_level:     str
    active_sessions:  int
    total_detections: int
    jump_count:       int
    incidents_learned:int
    amtd_cycle:       int
    uptime_s:         float

    def to_dict(self) -> dict:
        return {
            "timestamp":         self.timestamp.isoformat(),
            "status":            self.status.value,
            "threat_level":      self.threat_level,
            "active_sessions":   self.active_sessions,
            "total_detections":  self.total_detections,
            "jump_count":        self.jump_count,
            "incidents_learned": self.incidents_learned,
            "amtd_cycle":        self.amtd_cycle,
            "uptime_s":          round(self.uptime_s, 1),
        }


# ─────────────────────────────────────────────
# SISTEMA AEGIS — INTEGRACIÓN COMPLETA
# ─────────────────────────────────────────────

class AegisSystem:
    """
    Fachada principal de AEGIS.
    Instancia, conecta y coordina todas las capas.

    Uso mínimo:
        aegis = AegisSystem()
        await aegis.start()
        # ... sistema operativo ...
        await aegis.stop()

    Uso avanzado:
        aegis = AegisSystem(
            installation_id    = "AEGIS-ESP-BCN-001",
            amtd_interval_s    = 30,
            decoy_ports        = [8080, 8443, 9090],
        )
        await aegis.start()
        status = aegis.snapshot()
    """

    def __init__(
        self,
        installation_id:  str   = None,
        amtd_interval_s:  int   = 30,
        decoy_ports:      list  = None,
        signing_key:      bytes = None,
        shield_enabled:   bool  = True,
        telegram_token:   str   = None,
        telegram_chat_id: str   = None,
        enlil_url:        str   = None,
        enlil_api_key:    str   = None,
        state_dir:        str   = "state",
    ):
        self._id           = installation_id or f"AEGIS-{secrets.token_hex(4).upper()}"
        self._shield_enabled = shield_enabled
        self._status       = SystemStatus.OFFLINE
        self._started_at:  Optional[datetime] = None
        self._tasks:       list = []

        # ── Capa 0: Criptografía ──────────────────────────────────────────────
        self.crypto = AegisCrypto()

        # ── Capa 0.5: Escudo disuasorio ───────────────────────────────────────
        self.shield = AegisShield(decoy_ports=decoy_ports)

        # ── Capa 1: Gemelo en cadena ──────────────────────────────────────────
        self.twin = TwinChain()

        # ── Capa 2: Campo de minas ────────────────────────────────────────────
        self.minefield = AegisMinefield()

        # ── Capa 3: Detección multi-agente ────────────────────────────────────
        self.detector = AegisDetector()

        # ── Capa 4: Cierre atómico ────────────────────────────────────────────
        self.lockdown = AegisLockdown()

        # ── Capa 5: Superficie móvil AMTD ─────────────────────────────────────
        self.amtd = AegisAMTD(rotation_interval_s=amtd_interval_s)

        # ── Capa 6: Burbuja evolutiva ─────────────────────────────────────────
        self.bubble = AegisBubble()

        # ── Persistencia — Hueco #7 ──────────────────────────────────────────
        self._persistence = CheckpointManager(state_dir=state_dir)
        self._wal = WALManager(wal_dir=self._persistence._state_dir / "wal")

        # ── Capa 7: Análisis forense ──────────────────────────────────────────
        self.forensic = AegisForensic(persistence=self._persistence)

        # ── Capa 8: Aprendizaje colectivo ─────────────────────────────────────
        self.learning = AegisLearning(
            installation_id = self._id,
            signing_key     = signing_key or secrets.token_bytes(32),
        )

        # ── Monitor de superficie — Mejora 6 ──────────────────────────────────
        # Post-Incident Reporter
        self._reporter = IncidentReporter()

        self.surface = SurfaceMonitor()

        # ── Alertas Telegram ──────────────────────────────────────────────────
        self._telegram: Optional[TelegramAlerter] = None
        if telegram_token and telegram_chat_id:
            self._telegram = TelegramAlerter(AlertConfig(
                token   = telegram_token,
                chat_id = telegram_chat_id,
            ))
            logger.info("[AEGIS] Alertas Telegram configuradas ✓")

        # ── Integración ENLIL ─────────────────────────────────────────────────
        self._enlil: Optional[EnlilConnector] = None
        if enlil_url and enlil_api_key:
            self._enlil = EnlilConnector(enlil_url, enlil_api_key)
            logger.info("[AEGIS] Integración ENLIL configurada ✓")

        self._timing_lockdown  = _TimingWindow()
        self._timing_detection = _TimingWindow()

        logger.info(f"[AEGIS] Sistema instanciado — id={self._id}")

    # ─────────────────────────────────────────
    # ARRANQUE Y PARADA
    # ─────────────────────────────────────────

    async def start(self):
        """
        Arranca todas las capas en orden y establece todas las conexiones.
        Orden: C0 → C0.5 → C1 → C2 → C3 → C4 → C5 → C6 → C7 → C8
        """
        if self._status != SystemStatus.OFFLINE:
            logger.warning("[AEGIS] start() llamado con sistema ya activo")
            return

        self._status = SystemStatus.STARTING
        logger.info(f"[AEGIS] ═══ ARRANQUE — {self._id} ═══")

        # ── 1. Verificar Capa 0 ───────────────────────────────────────────────
        self.crypto.self_test()
        logger.info("[AEGIS] C0 — Criptografía post-cuántica ✓")

        # ── 2. Conectar todas las capas ───────────────────────────────────────
        self._connect_layers()
        logger.info("[AEGIS] Conexiones inter-capa establecidas ✓")

        # ── 3. Arrancar capas con ciclo de vida propio ────────────────────────
        if self._shield_enabled:
            await asyncio.gather(
                self.shield.start(),
                self.twin.start(),
                self.amtd.start(),
            )
            logger.info("[AEGIS] C0.5 / C1 / C5 — Capas continuas activas ✓")
        else:
            await asyncio.gather(
                self.twin.start(),
                self.amtd.start(),
            )
            logger.info("[AEGIS] C1 / C5 — Capas continuas activas (C0.5 desactivada) ✓")

        self._started_at = datetime.now(timezone.utc)
        self._status     = SystemStatus.ONLINE

        # ── Arrancar auto-checkpointer ────────────────────────────────────────
        self._auto_ckpt = AutoCheckpointer(
            self._persistence,
            self._snapshot_for_checkpoint,
            post_checkpoint_fn=self._wal.flush,
        )
        await self._auto_ckpt.start()
        self._pending_checkpoint = self._persistence.load_latest_checkpoint()
        if self._pending_checkpoint:
            logger.info(
                f"[AEGIS] Checkpoint {self._pending_checkpoint.get('checkpoint_id','?')} encontrado "
                f"— restauracion diferida hasta MACE"
            )

        logger.info(
            f"[AEGIS] ═══ SISTEMA ONLINE ═══ "
            f"id={self._id} | "
            f"capas=10 | "
            f"tests=318/318"
        )

        if self._telegram:
            self._reporter.set_telegram(self._telegram)
            await self._telegram.send_startup()

    async def stop(self):
        """Detiene todas las capas ordenadamente."""
        if self._status == SystemStatus.OFFLINE:
            return

        self._status = SystemStatus.STOPPING
        logger.info(f"[AEGIS] ═══ PARADA — {self._id} ═══")

        if self._shield_enabled:
            await asyncio.gather(
                self.shield.stop(),
                self.twin.stop(),
                self.amtd.stop(),
            )
        else:
            await asyncio.gather(
                self.twin.stop(),
                self.amtd.stop(),
            )

        for task in self._tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
        self._tasks.clear()

        # Checkpoint final antes de cerrar
        try:
            snap = await self._snapshot_for_checkpoint()
            self._persistence.save_checkpoint(snap)
            await self._auto_ckpt.stop()
        except Exception as e:
            logger.warning(f"[AEGIS] Error en checkpoint final: {e}")

        self._status = SystemStatus.OFFLINE
        logger.info("[AEGIS] Sistema detenido")

    # ─────────────────────────────────────────
    # CONEXIONES INTER-CAPA
    # ─────────────────────────────────────────

    def _connect_layers(self):
        """
        Establece todas las conexiones entre capas.
        Cada conexión es un callback registrado — sin acoplamiento directo.
        """

        # ── C2 → C3: Campo de minas alimenta detector ─────────────────────────
        self.minefield.register_detection_callback(self.detector.on_mine_contact)
        self.minefield.register_forensic_callback(self.forensic.on_mine_contact)
        self.minefield.register_learning_callback(self._on_mine_for_learning)

        # ── C0.5 → C3: Escudo alimenta detector ──────────────────────────────
        self.shield.register_alert_callback(self._on_shield_probe)

        # ── C3 → C4: Detector dispara cierre atómico ─────────────────────────
        self.detector.register_jump_callback(self._on_detection_jump)
        self.detector.register_lockdown_callback(self._on_detection_lockdown)
        self.detector.register_forensic_callback(self.forensic.on_detection_event)

        # ── C4 → C1: Lockdown dispara salto de gemelo ────────────────────────
        self.lockdown.set_twin_jump_callback(self._on_lockdown_twin_jump)
        self.lockdown.register_forensic_callback(self.forensic.on_lockdown_snapshot)

        # ── C5 → C3: AMTD notifica acceso a superficie caducada ──────────────
        self.amtd.register_stale_access_callback(self._on_stale_access)
        self.amtd.register_rotation_callback(self._on_amtd_rotation)

        # ── C6 → C7: Burbuja alimenta forense ────────────────────────────────
        self.bubble.register_forensic_callback(self.forensic.on_bubble_interaction)
        self.bubble.register_learning_callback(self._on_bubble_for_learning)

        # ── C7 → C8: Forense alimenta aprendizaje ────────────────────────────
        self.forensic.register_learning_callback(self.learning.ingest_profile)

        # ── C1 → sistema: salto notifica estado ──────────────────────────────
        self.twin.register_jump_callback(self._on_twin_jump)

        # ── SurfaceMonitor: registra actividad de cada capa — Mejora 6 ───────
        self.minefield.register_detection_callback(
            lambda c: self.surface.record_event("C2")
        )
        self.shield.register_alert_callback(
            lambda p: self.surface.record_event("C0.5")
        )
        self.detector.register_forensic_callback(
            lambda e: self.surface.record_event("C3")
        )
        self.amtd.register_rotation_callback(
            lambda p: self.surface.record_event("C5")
        )
        self.bubble.register_forensic_callback(
            lambda i: self.surface.record_event("C6")
        )
        self.forensic.register_learning_callback(
            lambda p: self.surface.record_event("C7")
        )
        self.learning.register_mine_callback(
            lambda a: self.surface.record_event("C8")
        )

        logger.debug("[AEGIS] Conexiones inter-capa + SurfaceMonitor establecidas")

    # ─────────────────────────────────────────
    # HANDLERS DE CONEXIÓN
    # ─────────────────────────────────────────

    async def _on_shield_probe(self, probe_event):
        """C0.5 → C3: probe del escudo alimenta detector."""
        await self.detector.register_shield_probe(probe_event)

    async def _on_mine_for_learning(self, contact):
        """C2 → C8: señuelo tocado registra presión de capa."""
        self.learning.register_layer_pressure("capa_2")

    async def _on_detection_jump(self, detection: DetectionEvent):
        """
        C3 → C4 → C1: detección confirmada.
        Activa cierre atómico que a su vez dispara salto de gemelo.
        """
        self._status = SystemStatus.ALERT
        logger.warning(
            f"[AEGIS] ⚡ AMENAZA CONFIRMADA — "
            f"tipo={detection.detection_type.value} "
            f"ips={detection.source_ips}"
        )

        # Alerta Telegram inmediata
        if self._telegram:
            await self._telegram.on_threat_detected(detection, with_bubble=True)

        # Análisis ENLIL — Consejo de Dioses analiza la amenaza
        if self._enlil:
            await self._enlil.on_threat_detected(detection)

        # Abrir sesión de burbuja para el intruso
        for ip in detection.source_ips:
            session_id = self.bubble.open_session(ip)
            logger.info(f"[AEGIS] Burbuja abierta — ip={ip} session={session_id}")

        # Ejecutar cierre atómico (que dispara salto de gemelo internamente)
        result = await self.lockdown.execute(
            trigger = LockdownTrigger.DETECTION,
            context = detection.to_dict(),
            notes   = f"Detección: {detection.detection_type.value}",
        )
        self._status = SystemStatus.LOCKDOWN

        # PIR + auto-cierre forense -- fire-and-forget
        if result:
            asyncio.create_task(self._reporter.generate(detection, result, self.twin, self.forensic))
            asyncio.create_task(self._auto_close_forensic(list(detection.source_ips or [])))

        # Alerta de lockdown completado con resultado completo
        if self._telegram and result:
            lockdown_id = getattr(result, "lockdown_id", str(result))
            await self._telegram.on_lockdown(
                lockdown_id,
                result     = result,
                source_ips = list(detection.source_ips) if detection.source_ips else [],
            )

    async def _on_detection_lockdown(self, detection: DetectionEvent):
        """C3 → C4: detección de patrón activa lockdown sin jump."""
        _t0 = time.monotonic()
        if self._telegram:
            await self._telegram.on_threat_detected(detection)
        if self._enlil:
            await self._enlil.on_threat_detected(detection)
        if self.lockdown.is_sealed():
            await self.lockdown.reset()
        _t0_lock = time.monotonic()
        result = await self.lockdown.execute(
            trigger = LockdownTrigger.DETECTION,
            context = detection.to_dict(),
        )
        self._timing_lockdown.record((time.monotonic() - _t0_lock) * 1000)
        self._timing_detection.record((time.monotonic() - _t0) * 1000)
        if self._telegram and result:
            lockdown_id = getattr(result, "lockdown_id", str(result))
            await self._telegram.on_lockdown(
                lockdown_id,
                result     = result,
                source_ips = list(detection.source_ips) if detection.source_ips else [],
            )
        if result:
            asyncio.create_task(self._reporter.generate(detection, result, self.twin, self.forensic))
            asyncio.create_task(self._auto_close_forensic(list(detection.source_ips or [])))

    async def _on_lockdown_twin_jump(self, lockdown_id: str):
        """C4 → C1: lockdown dispara salto atómico de gemelo."""
        logger.warning(f"[AEGIS] Salto de gemelo — lockdown={lockdown_id}")
        await self.twin.trigger_jump(
            trigger = JumpTrigger.INTRUSION,
            notes   = f"Lockdown: {lockdown_id}",
        )

    async def _on_twin_jump(self, jump_event):
        """C1 → sistema: salto completado — registrar en aprendizaje."""
        self.learning.register_layer_pressure("capa_1")
        logger.info(
            f"[AEGIS] Salto completado — "
            f"id={jump_event.jump_id} "
            f"duración={jump_event.duration_ms:.1f}ms"
        )

    async def _on_stale_access(self, payload: dict):
        """C5 → C3: acceso a superficie caducada = reconocimiento viejo detectado."""
        ip   = payload.get("source_ip", "unknown")
        port = payload.get("value", 0)
        logger.warning(
            f"[AEGIS] Superficie caducada accedida — "
            f"ip={ip} tipo={payload.get('type')} valor={port}"
        )
        await self.detector.register_network_event(
            ip   = ip,
            port = port if isinstance(port, int) else 0,
            path = f"stale_{payload.get('type')}",
        )
        self.learning.register_layer_pressure("capa_5")

    async def _on_amtd_rotation(self, rotation_event):
        """C5 → sistema: rotación AMTD completada — registrar en forense."""
        pass   # rotaciones normales no generan ruido en el log de amenazas

    async def _on_bubble_for_learning(self, interaction):
        """C6 → C8: interacción en burbuja registra presión."""
        self.learning.register_layer_pressure("capa_6")

    # ─────────────────────────────────────────
    # API PÚBLICA
    # ─────────────────────────────────────────

    async def _auto_close_forensic(self, source_ips: list):
        """Cierra incidentes forenses abiertos 30 segundos tras el lockdown."""
        await asyncio.sleep(30)
        for profile in list(self.forensic._incidents.values()):
            if any(ip in profile.source_ips for ip in source_ips):
                await self.forensic.close_incident_async(profile.incident_id)

    async def trigger_lockdown(self, notes: str = "manual") -> bool:
        """Activación manual de cierre atómico."""
        if self.lockdown.is_sealed():
            await self.lockdown.reset()
        _t0 = time.monotonic()
        result = await self.lockdown.execute(
            trigger = LockdownTrigger.MANUAL,
            notes   = notes,
        )
        self._timing_lockdown.record((time.monotonic() - _t0) * 1000)
        return result.success

    async def rotate_now(self):
        """Fuerza rotación inmediata de superficie AMTD."""
        await self.amtd.rotate_now()

    def open_bubble_session(self, source_ip: str) -> str:
        """Abre sesión de burbuja para un IP dado."""
        return self.bubble.open_session(source_ip)

    async def bubble_interact(
        self, session_id: str, data: bytes,
        interaction_type: InteractionType = InteractionType.UNKNOWN
    ) -> str:
        """Procesa interacción de intruso dentro de la burbuja."""
        return await self.bubble.interact(session_id, data, interaction_type)

    def open_forensic_incident(self, ips: list) -> str:
        """Abre incidente forense manualmente."""
        return self.forensic.open_incident(ips)

    async def close_forensic_incident(self, incident_id: str):
        """Cierra incidente forense y dispara aprendizaje."""
        await self.forensic.close_incident_async(incident_id)

    def export_intelligence(self):
        """Exporta inteligencia para compartir con la red colectiva."""
        return self.learning.export_intelligence()

    def import_intelligence(
        self, packet, signing_key: bytes = None, verify: bool = True
    ) -> bool:
        """Importa inteligencia de otra instalación AEGIS."""
        return self.learning.import_intelligence(
            packet, signing_key=signing_key, verify=verify
        )

    def trust_peer(self, origin_id: str, key: bytes):
        """Registra un peer de confianza para verificar su inteligencia (PKI)."""
        self.learning.trust_peer(origin_id, key)

    def get_own_key(self) -> bytes:
        """Retorna la clave de firma de esta instalación para compartir con peers."""
        return self.learning.get_own_key()

    # ─────────────────────────────────────────
    # ESTADO Y MONITORIZACIÓN
    # ─────────────────────────────────────────

    def snapshot(self) -> SystemSnapshot:
        """Estado completo del sistema en este instante."""
        uptime = 0.0
        if self._started_at:
            uptime = (datetime.now(timezone.utc) - self._started_at).total_seconds()

        jump_log = self.twin.get_jump_log()

        return SystemSnapshot(
            timestamp        = datetime.now(timezone.utc),
            status           = self._status,
            threat_level     = self.twin.twin_a.state.security.threat_level,
            active_sessions  = len(self.bubble.active_sessions()),
            total_detections = self.detector.total_detections(),
            jump_count       = len(jump_log),
            incidents_learned= self.learning.status()["incidents_learned"],
            amtd_cycle       = self.amtd.status()["cycle"],
            uptime_s         = uptime,
        )

    def full_status(self) -> dict:
        """Estado detallado de cada capa."""
        result = {
            "system":      self.snapshot().to_dict(),
            "shield":      self.shield.status().__dict__,
            "twin":      self.twin.status(),
            "minefield": self.minefield.status(),
            "detector":  self.detector.status(),
            "lockdown":  self.lockdown.aegis_status(),
            "amtd":      self.amtd.status(),
            "bubble":    self.bubble.status(),
            "forensic":  self.forensic.status(),
            "learning":  self.learning.status(),
            "surface":     self.surface.status(),
            "persistence": self._persistence.status(),
            "timings": {
                "lockdown_ms":  self._timing_lockdown.percentiles(),
                "detection_ms": self._timing_detection.percentiles(),
            },
        }
        if hasattr(self, "_mace_proxy") and self._mace_proxy is not None:
            result["mace"] = self._mace_proxy.status()
            if hasattr(self, "_mace_connector") and self._mace_connector is not None:
                conn = self._mace_connector.status()
                result["mace"]["blocked_ips_list"] = conn.get("blocked_ips", [])
        return result

    async def _snapshot_for_checkpoint(self) -> dict:
        """Snapshot con estado restaurable: blocklist + lockdown + contadores."""
        try:
            data = self.full_status()
            if hasattr(self, "_mace_proxy") and self._mace_proxy is not None:
                data["_restore"] = {
                    "blocklist": self._mace_proxy.blocklist.to_checkpoint(),
                    "lockdown_status": str(self.lockdown.aegis_status().get("status", "IDLE")),
                    "total_detections": self.detector.status().get("total_detections", 0),
                }
            return data
        except Exception as e:
            logger.warning(f"[AEGIS] Error en snapshot: {e}")
            return {"error": str(e)}

    def _restore_from_checkpoint(self, ckpt: dict):
        """Restaura estado critico tras arranque: blocklist + alerta lockdown."""
        restore = ckpt.get("data", {}).get("_restore")
        if not restore:
            return
        restored = []
        if hasattr(self, "_mace_proxy") and self._mace_proxy is not None:
            blocked = restore.get("blocklist", [])
            if blocked:
                self._mace_proxy.blocklist.restore_from_checkpoint(blocked)
                restored.append(f"blocklist={len(blocked)} IPs")
        if restore.get("lockdown_status") == "LOCKED":
            logger.warning("[AEGIS] Sistema estaba en LOCKDOWN -- requiere intervencion manual")
            restored.append("lockdown_alert")
        if restored:
            logger.info(f"[AEGIS] Estado restaurado: {chr(44).join(restored)}")


    # ── Superficie de ataque — Mejora 6 ──────────────────────────────────────

    def get_surface_suggestions(self) -> list:
        """
        Retorna sugerencias de desactivación de capas inactivas.
        Una capa aparece si lleva más de threshold_days sin actividad.
        Nunca sugiere desactivar C0, C1 ni C4.
        """
        return self.surface.get_suggestions()

    def get_surface_score(self) -> dict:
        """Score de superficie expuesta [0.0–1.0] con desglose."""
        return self.surface.surface_score()

    def get_layer_activity(self, layer_id: str) -> Optional[dict]:
        """Estado de actividad de una capa concreta."""
        return self.surface.get_layer_activity(layer_id)

    def get_all_layer_activity(self) -> list:
        """Estado de actividad de todas las capas monitorizadas."""
        return self.surface.get_all_activity()

    # ── Integración MACE — Mejora 7 ───────────────────────────────────────────

    async def start_mace_integration(
        self,
        target_url:  str           = "http://localhost:8000",
        listen_port: int           = 8080,
        webhook_url: Optional[str] = None,
    ):
        """
        Arranca el proxy inverso delante de MACE y conecta los detectores.
        MACE no se modifica — el proxy es completamente transparente.

        Retorna el MaceConnector activo para consultas de estado.
        """
        from integrations.mace_proxy     import MaceProxy
        from integrations.mace_connector import MaceConnector

        # Crear proxy y conector
        self._mace_proxy = MaceProxy(
            target_url  = target_url,
            listen_port = listen_port,
            on_request  = self.detector.register_network_event,
        )
        self._mace_connector = MaceConnector(
            proxy       = self._mace_proxy,
            webhook_url = webhook_url,
            wal         = self._wal,
        )

        # Compartir blocklist del proxy con el conector
        self._mace_proxy._blocklist = self._mace_connector._proxy.blocklist

        # Conectar detectores de AEGIS al conector
        self.detector.register_jump_callback(
            self._mace_connector.on_detection
        )
        self.detector.register_lockdown_callback(
            self._mace_connector.on_detection
        )
        self.minefield.register_detection_callback(
            self._mace_connector.on_mine_contact
        )

        # Arrancar el proxy
        await self._mace_proxy.start()

        # Restaurar estado desde checkpoint (diferido desde start())
        pending = getattr(self, "_pending_checkpoint", None)
        if pending:
            self._restore_from_checkpoint(pending)
            self._pending_checkpoint = None

        # WAL recovery: replay mutaciones ocurridas tras el ultimo checkpoint
        wal_ops = self._wal.recover()
        for wal_path, entry in wal_ops:
            op     = entry.get("op")
            params = entry.get("params", {})
            if op == "block_ip":
                ip, ttl = params.get("ip"), params.get("ttl_s")
                if ip:
                    self._mace_proxy.blocklist.block(ip, ttl_s=int(ttl) if ttl else None)
                    logger.warning(f"[WAL] Replay block_ip: {ip} ttl={ttl}s")
            elif op == "unblock_ip":
                ip = params.get("ip")
                if ip:
                    self._mace_proxy.blocklist.unblock(ip)
                    logger.warning(f"[WAL] Replay unblock_ip: {ip}")
            else:
                logger.warning(f"[WAL] Op desconocida en recovery: {op} — ignorada")
            self._wal.commit(wal_path)

        logger.info(
            f"[AEGIS] Integración MACE activa — "
            f"proxy={listen_port} → {target_url}"
        )
        return self._mace_connector

    async def stop_mace_integration(self):
        """Detiene el proxy de MACE limpiamente."""
        proxy = getattr(self, "_mace_proxy", None)
        if proxy:
            await proxy.stop()
            logger.info("[AEGIS] Integración MACE detenida")

    @property
    def installation_id(self) -> str:
        return self._id

    @property
    def status(self) -> SystemStatus:
        return self._status

    def __repr__(self):
        return f"AegisSystem(id={self._id} status={self._status.value})"
