"""
AEGIS — Capa 8: Aprendizaje Colectivo
=======================================
AEGIS aprende de cada intrusión y mejora sus defensas.

QUÉ APRENDE:
    - Qué señuelos fueron más efectivos en detectar al intruso
    - Qué comportamientos de burbuja lo mantuvieron más tiempo
    - Por dónde intentó escapar (qué capas forzó más)
    - Qué técnicas usó → cómo ajustar umbrales del detector

QUÉ HACE CON LO APRENDIDO:
    - Actualiza pesos de efectividad de señuelos (Capa 2)
    - Ajusta parámetros de la burbuja (Capa 6)
    - Refuerza capas donde el intruso ejerció más presión
    - Genera inteligencia compartible entre instalaciones AEGIS

RED COLECTIVA:
    - Cada instalación exporta su inteligencia en formato estándar
    - Cada instalación importa inteligencia de otras
    - Sin datos personales — solo patrones y ajustes
    - Firma criptográfica en cada paquete de inteligencia

MÓDULO: layers/learning.py
"""

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("aegis.learning")


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class LearningSignal(str, Enum):
    MINE_EFFECTIVE      = "MINE_EFFECTIVE"       # señuelo detectó al intruso
    MINE_INEFFECTIVE    = "MINE_INEFFECTIVE"     # señuelo ignorado
    BUBBLE_HELD         = "BUBBLE_HELD"          # burbuja retuvo al intruso
    LAYER_PRESSURED     = "LAYER_PRESSURED"      # capa recibió presión de escape
    TECHNIQUE_OBSERVED  = "TECHNIQUE_OBSERVED"   # nueva técnica identificada
    INTENT_CONFIRMED    = "INTENT_CONFIRMED"     # intención confirmada


# ─────────────────────────────────────────────
# PAQUETE DE INTELIGENCIA — compartible entre instalaciones
# ─────────────────────────────────────────────

@dataclass
class IntelligencePacket:
    """
    Paquete de inteligencia exportable a la red colectiva.
    Sin datos personales — solo patrones y ajustes estadísticos.
    Firmado criptográficamente para garantizar origen.
    """
    packet_id:        str
    origin_id:        str          # ID anónimo de la instalación origen
    generated_at:     datetime
    aegis_version:    str = "1.0"

    # Señuelos más efectivos
    effective_mines:  list = field(default_factory=list)   # tipos de señuelo

    # Técnicas observadas con frecuencia
    technique_freq:   dict = field(default_factory=dict)   # técnica → count

    # Ajustes de umbrales recomendados
    threshold_deltas: dict = field(default_factory=dict)   # parámetro → delta

    # Patrones de actor
    actor_distribution: dict = field(default_factory=dict) # tipo → porcentaje

    # Intenciones más comunes
    intent_freq:      dict = field(default_factory=dict)

    # Firma del paquete
    signature:        str = ""

    def sign(self, key: bytes) -> str:
        """Firma el paquete con HMAC-SHA256."""
        payload = json.dumps({
            "packet_id":      self.packet_id,
            "origin_id":      self.origin_id,
            "generated_at":   self.generated_at.isoformat(),
            "effective_mines":sorted(self.effective_mines),
            "technique_freq": self.technique_freq,
        }, sort_keys=True).encode()
        self.signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return self.signature

    def verify(self, key: bytes) -> bool:
        """Verifica la firma del paquete."""
        saved = self.signature
        self.sign(key)
        valid = hmac.compare_digest(saved, self.signature)
        self.signature = saved
        return valid

    def to_dict(self) -> dict:
        return {
            "packet_id":         self.packet_id,
            "origin_id":         self.origin_id,
            "generated_at":      self.generated_at.isoformat(),
            "aegis_version":     self.aegis_version,
            "effective_mines":   self.effective_mines,
            "technique_freq":    self.technique_freq,
            "threshold_deltas":  self.threshold_deltas,
            "actor_distribution":self.actor_distribution,
            "intent_freq":       self.intent_freq,
            "signature":         self.signature,
        }


# ─────────────────────────────────────────────
# BASE DE CONOCIMIENTO LOCAL
# ─────────────────────────────────────────────

@dataclass
class KnowledgeBase:
    """
    Base de conocimiento local de una instalación AEGIS.
    Acumula aprendizaje de todos los incidentes procesados.
    """
    # Efectividad de señuelos — mine_type → [0.0, 1.0]
    mine_effectiveness: dict = field(default_factory=dict)

    # Frecuencia de técnicas observadas
    technique_counts:   dict = field(default_factory=dict)

    # Frecuencia de tipos de actor
    actor_counts:       dict = field(default_factory=dict)

    # Frecuencia de intenciones
    intent_counts:      dict = field(default_factory=dict)

    # Presión por capa — qué capas recibieron más intentos de escape
    layer_pressure:     dict = field(default_factory=dict)

    # Tiempos de retención en burbuja
    bubble_durations_s: list = field(default_factory=list)

    # Número de incidentes procesados
    incident_count:     int  = 0

    def update_mine(self, mine_type: str, detected: bool):
        """Actualiza la efectividad de un tipo de señuelo."""
        if mine_type not in self.mine_effectiveness:
            self.mine_effectiveness[mine_type] = {"hits": 0, "total": 0}
        self.mine_effectiveness[mine_type]["total"] += 1
        if detected:
            self.mine_effectiveness[mine_type]["hits"] += 1

    def mine_hit_rate(self, mine_type: str) -> float:
        """Tasa de éxito de un tipo de señuelo."""
        data = self.mine_effectiveness.get(mine_type)
        if not data or data["total"] == 0:
            return 0.0
        return data["hits"] / data["total"]

    def top_mines(self, n: int = 3) -> list:
        """Señuelos más efectivos por tasa de detección."""
        rates = {
            mt: self.mine_hit_rate(mt)
            for mt in self.mine_effectiveness
            if self.mine_effectiveness[mt]["total"] > 0
        }
        return sorted(rates, key=rates.get, reverse=True)[:n]

    def update_technique(self, technique: str):
        self.technique_counts[technique] = self.technique_counts.get(technique, 0) + 1

    def update_actor(self, actor_type: str):
        self.actor_counts[actor_type] = self.actor_counts.get(actor_type, 0) + 1

    def update_intent(self, intent: str):
        self.intent_counts[intent] = self.intent_counts.get(intent, 0) + 1

    def update_layer_pressure(self, layer: str):
        self.layer_pressure[layer] = self.layer_pressure.get(layer, 0) + 1

    def most_pressured_layer(self) -> Optional[str]:
        if not self.layer_pressure:
            return None
        return max(self.layer_pressure, key=self.layer_pressure.get)

    def avg_bubble_retention_s(self) -> float:
        if not self.bubble_durations_s:
            return 0.0
        return statistics.mean(self.bubble_durations_s)

    def to_dict(self) -> dict:
        return {
            "incident_count":      self.incident_count,
            "mine_effectiveness":  self.mine_effectiveness,
            "technique_counts":    self.technique_counts,
            "actor_counts":        self.actor_counts,
            "intent_counts":       self.intent_counts,
            "layer_pressure":      self.layer_pressure,
            "avg_bubble_retention_s": self.avg_bubble_retention_s(),
            "top_mines":           self.top_mines(),
        }


# ─────────────────────────────────────────────
# RASTREADOR DE SECUENCIAS — Mejora 1: Aprendizaje Anticipatorio
# ─────────────────────────────────────────────

class SequenceTracker:
    """
    Registra y analiza secuencias de tipos de señuelo tocados por atacantes.
    Aprende qué mine_type suele seguir a qué otro mine_type.

    Ejemplo: si históricamente FILE → CREDENTIAL ocurre en el 80% de los
    casos, al tocar FILE predice que el siguiente será CREDENTIAL y prepara
    ese señuelo para que sea el más convincente posible.

    Estructura interna:
        _transitions[A][B] = N  → A fue seguido de B exactamente N veces
        _totals[A]         = N  → A fue el paso inicial N veces en total

    Predicción:
        P(B | A) = _transitions[A][B] / _totals[A]
        Se retorna el B con mayor probabilidad condicional.
        Si no hay historia suficiente → None (sin predicción).
    """

    MIN_OBSERVATIONS = 3   # mínimo de observaciones para predecir

    def __init__(self):
        self._transitions: dict = {}   # {mine_a: {mine_b: count}}
        self._totals:      dict = {}   # {mine_a: total_seguidos}

    def record_sequence(self, mine_types: list):
        """
        Registra la secuencia completa de un incidente.
        mine_types = ["MineType.FILE", "MineType.CREDENTIAL", "MineType.ENDPOINT"]
        """
        if len(mine_types) < 2:
            return   # secuencia de 1 no enseña transiciones

        for i in range(len(mine_types) - 1):
            a = mine_types[i]
            b = mine_types[i + 1]

            if a not in self._transitions:
                self._transitions[a] = {}
            self._transitions[a][b] = self._transitions[a].get(b, 0) + 1
            self._totals[a]         = self._totals.get(a, 0) + 1

    def predict_next(self, current_mine_type: str) -> Optional[dict]:
        """
        Dado el tipo de señuelo que acaba de tocarse, predice el siguiente.

        Retorna dict con:
            predicted_mine:  str    — tipo de señuelo predicho
            confidence:      float  — probabilidad condicional [0.0, 1.0]
            observations:    int    — número de transiciones observadas

        Retorna None si no hay historia suficiente.
        """
        transitions = self._transitions.get(current_mine_type, {})
        total       = self._totals.get(current_mine_type, 0)

        if total < self.MIN_OBSERVATIONS:
            return None   # muy pocos datos — no predecimos

        # Encontrar el sucesor más frecuente
        best_next  = max(transitions, key=transitions.get)
        best_count = transitions[best_next]
        confidence = best_count / total

        return {
            "predicted_mine": best_next,
            "confidence":     round(confidence, 3),
            "observations":   total,
            "all_transitions": {
                k: round(v / total, 3)
                for k, v in sorted(
                    transitions.items(), key=lambda x: x[1], reverse=True
                )
            },
        }

    def predict_sequence(self, current_mine_type: str, depth: int = 3) -> list:
        """
        Predice los próximos `depth` pasos a partir del tipo actual.
        Útil para preparar varios señuelos de antemano.
        Retorna lista de dicts con predicted_mine y confidence.
        Para cuando la confianza cae por debajo del 30% se para.
        """
        predictions = []
        current     = current_mine_type
        MIN_CONFIDENCE = 0.30

        for _ in range(depth):
            pred = self.predict_next(current)
            if pred is None or pred["confidence"] < MIN_CONFIDENCE:
                break
            predictions.append(pred)
            current = pred["predicted_mine"]

        return predictions

    def most_common_first_step(self) -> Optional[str]:
        """El tipo de señuelo con el que más frecuentemente empieza un ataque."""
        if not self._totals:
            return None
        return max(self._totals, key=self._totals.get)

    def to_dict(self) -> dict:
        return {
            "transitions": self._transitions,
            "totals":      self._totals,
        }


# ─────────────────────────────────────────────
# MOTOR DE AJUSTE — traduce aprendizaje en acciones
# ─────────────────────────────────────────────

class AdjustmentEngine:
    """
    Traduce el conocimiento acumulado en ajustes concretos para otras capas.

    AJUSTES QUE GENERA:
        → Capa 2 (minefield): promover señuelos más efectivos, añadir variantes
        → Capa 3 (detector):  ajustar umbrales de detección según técnicas vistas
        → Capa 6 (bubble):    optimizar latencias según tiempo de retención
    """

    def compute_mine_adjustments(self, kb: KnowledgeBase) -> dict:
        """
        Genera ajustes para Capa 2.
        Señuelos con alta tasa de detección → promover.
        Señuelos nunca tocados → considerar variantes.
        """
        adjustments = {}
        for mine_type, data in kb.mine_effectiveness.items():
            rate = kb.mine_hit_rate(mine_type)
            if rate >= 0.8:
                adjustments[mine_type] = {"action": "PROMOTE", "rate": rate}
            elif rate < 0.2 and data["total"] >= 3:
                adjustments[mine_type] = {"action": "VARY", "rate": rate}
            else:
                adjustments[mine_type] = {"action": "MAINTAIN", "rate": rate}
        return adjustments

    def compute_detector_adjustments(self, kb: KnowledgeBase) -> dict:
        """
        Genera ajustes de umbrales para Capa 3.
        Si una técnica es muy frecuente → bajar umbral de detección.
        """
        adjustments = {}
        total = sum(kb.technique_counts.values()) or 1
        for technique, count in kb.technique_counts.items():
            freq = count / total
            if freq >= 0.5:
                # Técnica dominante — detectar más agresivamente
                adjustments[technique] = {"threshold_delta": -0.1, "freq": freq}
            elif freq <= 0.1:
                # Técnica rara — umbral normal
                adjustments[technique] = {"threshold_delta": 0.0, "freq": freq}
            else:
                adjustments[technique] = {"threshold_delta": -0.05, "freq": freq}
        return adjustments

    def compute_bubble_adjustments(self, kb: KnowledgeBase) -> dict:
        """
        Genera ajustes para Capa 6.
        Si el tiempo de retención es bajo → aumentar complejidad del engaño.
        """
        avg_retention = kb.avg_bubble_retention_s()
        if avg_retention == 0:
            return {"action": "MAINTAIN"}
        if avg_retention < 30:
            return {"action": "INCREASE_COMPLEXITY", "avg_retention_s": avg_retention}
        elif avg_retention >= 120:
            return {"action": "MAINTAIN", "avg_retention_s": avg_retention}
        else:
            return {"action": "OPTIMIZE", "avg_retention_s": avg_retention}

    def compute_layer_reinforcement(self, kb: KnowledgeBase) -> dict:
        """
        Identifica capas que necesitan refuerzo.
        La capa con más presión → prioridad de refuerzo.
        """
        if not kb.layer_pressure:
            return {}
        total = sum(kb.layer_pressure.values())
        return {
            layer: {
                "pressure_count": count,
                "pressure_pct":   round(count / total, 3),
                "priority":       "HIGH" if count / total >= 0.4 else "MEDIUM",
            }
            for layer, count in kb.layer_pressure.items()
        }


# ─────────────────────────────────────────────
# RED COLECTIVA — Mejora 3: Sync automático
# ─────────────────────────────────────────────

class CollectiveNetwork:
    """
    Gestiona la red de instalaciones AEGIS pares.
    Ejecuta export/import de inteligencia automáticamente cada
    `sync_interval_s` segundos — sin intervención manual.

    DISEÑO:
        Cada instalación conoce a sus pares vía register_peer().
        En cada ciclo: exporta su inteligencia y llama al peer_callback
        de cada par para que la importe. El callback puede ser local
        (tests) o remoto (futura integración de red real).

    SIN DATOS PERSONALES:
        Solo se comparten IntelligencePackets firmados — patrones,
        no eventos concretos ni IPs reales.
    """

    DEFAULT_SYNC_INTERVAL_S = 300   # 5 minutos por defecto

    def __init__(self, sync_interval_s: int = None):
        self._sync_interval_s  = sync_interval_s or self.DEFAULT_SYNC_INTERVAL_S
        self._peers:       list = []   # lista de {peer_id, callback}
        self._sync_log:    list = []   # historial de syncs realizados
        self._task: Optional[asyncio.Task] = None
        self._running      = False
        self._sync_count   = 0
        self._last_sync_at: Optional[datetime] = None

    def register_peer(self, peer_id: str, import_callback: Callable):
        """
        Registra una instalación par.
        import_callback(packet) será llamado con el IntelligencePacket
        exportado en cada ciclo de sync.
        """
        # Evitar duplicados
        if any(p["peer_id"] == peer_id for p in self._peers):
            return
        self._peers.append({
            "peer_id":  peer_id,
            "callback": import_callback,
            "syncs":    0,
        })
        logger.info(f"[NET] Par registrado: {peer_id} — {len(self._peers)} pares activos")

    def unregister_peer(self, peer_id: str):
        """Elimina un par de la red."""
        self._peers = [p for p in self._peers if p["peer_id"] != peer_id]

    async def sync_once(self, export_fn: Callable) -> int:
        """
        Ejecuta un ciclo de sync manual:
            1. Exporta inteligencia local con export_fn()
            2. La envía a todos los pares registrados
        Retorna número de pares sincronizados con éxito.
        """
        if not self._peers:
            return 0

        packet  = export_fn()
        ok      = 0
        errores = []

        for peer in self._peers:
            try:
                cb = peer["callback"]
                if asyncio.iscoroutinefunction(cb):
                    result = await cb(packet)
                else:
                    result = cb(packet)

                if result is not False:   # None también cuenta como OK
                    peer["syncs"] += 1
                    ok += 1
            except Exception as e:
                errores.append({"peer": peer["peer_id"], "error": str(e)})
                logger.warning(
                    f"[NET] Error sync con {peer['peer_id']}: {e}"
                )

        self._sync_count  += 1
        self._last_sync_at = datetime.now(timezone.utc)
        self._sync_log.append({
            "sync_id":   self._sync_count,
            "timestamp": self._last_sync_at.isoformat(),
            "peers_ok":  ok,
            "peers_err": len(errores),
            "errores":   errores,
        })

        logger.info(
            f"[NET] Sync #{self._sync_count} — "
            f"{ok}/{len(self._peers)} pares sincronizados"
        )
        return ok

    async def _sync_loop(self, export_fn: Callable):
        """Bucle automático — sincroniza cada _sync_interval_s segundos."""
        logger.info(
            f"[NET] Red colectiva activa — "
            f"intervalo={self._sync_interval_s}s "
            f"pares={len(self._peers)}"
        )
        while self._running:
            try:
                await asyncio.sleep(self._sync_interval_s)
                if self._running and self._peers:
                    await self.sync_once(export_fn)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[NET] Error en bucle de sync: {e}")
                await asyncio.sleep(10)   # pausa breve antes de reintentar

    async def start(self, export_fn: Callable):
        """Inicia el bucle automático de sincronización."""
        if self._running:
            return
        self._running = True
        self._task    = asyncio.create_task(
            self._sync_loop(export_fn), name="aegis.learning.net"
        )

    async def stop(self):
        """Detiene el bucle automático."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("[NET] Red colectiva detenida")

    def status(self) -> dict:
        return {
            "peers":            len(self._peers),
            "peer_ids":         [p["peer_id"] for p in self._peers],
            "sync_count":       self._sync_count,
            "sync_interval_s":  self._sync_interval_s,
            "last_sync_at":     self._last_sync_at.isoformat()
                                if self._last_sync_at else None,
            "running":          self._running,
        }

    def get_sync_log(self) -> list:
        return list(self._sync_log)


# ─────────────────────────────────────────────
# FACHADA PRINCIPAL — AegisLearning
# ─────────────────────────────────────────────

class AegisLearning:
    """
    Fachada de Capa 8 — Aprendizaje Colectivo.

    Uso:
        learning = AegisLearning(installation_id="AEGIS-ESP-001")

        # Conectar como receptor de Capa 7:
        forensic.register_learning_callback(learning.ingest_profile)

        # Generar y exportar inteligencia:
        packet = learning.export_intelligence()

        # Importar inteligencia de otra instalación:
        learning.import_intelligence(packet, verify=True)

        # Obtener ajustes para aplicar a otras capas:
        adjustments = learning.get_adjustments()
    """

    def __init__(
        self,
        installation_id:  str   = None,
        signing_key:      bytes = None,
        sync_interval_s:  int   = None,
    ):
        self._installation_id = installation_id or f"AEGIS-{secrets.token_hex(4).upper()}"
        self._signing_key     = signing_key or secrets.token_bytes(32)

        # PKI — Hueco #8: mapa de peers de confianza origin_id → signing_key
        self._trusted_peers: dict = {}

        self._kb              = KnowledgeBase()
        self._engine          = AdjustmentEngine()
        self._seq_tracker     = SequenceTracker()          # Mejora 1
        self._network         = CollectiveNetwork(         # Mejora 3
            sync_interval_s=sync_interval_s
        )
        self._signals:        list = []
        self._imported:       list = []
        self._MAX_IMPORTED = 1000

        self._callbacks_mine:     list = []
        self._callbacks_detector: list = []
        self._callbacks_bubble:   list = []

        # Validación cruzada — Hueco #6
        self._holdout_signals: list = []  # 20% validación
        self._train_signals:   list = []  # 80% entrenamiento
        self._cv_divergence_warned = False

        logger.info(
            f"[AEGIS.Learning] Capa 8 inicializada — "
            f"instalación={self._installation_id}"
        )

    # ── Callbacks de aplicación ───────────────────────────────────────────────

    def register_mine_callback(self, cb: Callable):
        """Capa 2 — recibe ajustes de señuelos."""
        self._callbacks_mine.append(cb)

    def register_detector_callback(self, cb: Callable):
        """Capa 3 — recibe ajustes de umbrales."""
        self._callbacks_detector.append(cb)

    def register_bubble_callback(self, cb: Callable):
        """Capa 6 — recibe ajustes de comportamiento."""
        self._callbacks_bubble.append(cb)

    # ── Ingesta de perfiles desde Capa 7 ─────────────────────────────────────

    async def ingest_profile(self, profile) -> None:
        """
        Ingesta un perfil forense completo de Capa 7.
        Extrae todas las señales de aprendizaje del perfil.
        """
        self._kb.incident_count += 1

        # Señuelos que detectaron al intruso
        mine_sequence = []   # para aprendizaje anticipatorio (Mejora 1)
        for contact in getattr(profile, "mine_contacts", []):
            mine_type = str(getattr(contact, "mine_type", "UNKNOWN"))
            self._kb.update_mine(mine_type, detected=True)
            self._emit_signal(LearningSignal.MINE_EFFECTIVE, {"mine_type": mine_type})
            mine_sequence.append(mine_type)

        # Registrar secuencia completa en el tracker anticipatorio
        if len(mine_sequence) >= 2:
            self._seq_tracker.record_sequence(mine_sequence)

        # Técnicas observadas
        for technique in getattr(profile, "techniques", []):
            tech_str = str(technique.value if hasattr(technique, "value") else technique)
            self._kb.update_technique(tech_str)
            self._emit_signal(LearningSignal.TECHNIQUE_OBSERVED, {"technique": tech_str})

        # Tipo de actor
        actor = getattr(profile, "actor_type", None)
        if actor:
            self._kb.update_actor(str(actor.value if hasattr(actor, "value") else actor))

        # Intención
        intent = getattr(profile, "intent", None)
        if intent:
            intent_str = str(intent.value if hasattr(intent, "value") else intent)
            self._kb.update_intent(intent_str)
            self._emit_signal(LearningSignal.INTENT_CONFIRMED, {"intent": intent_str})

        # Tiempo de retención en burbuja (si disponible)
        bubble_ints = getattr(profile, "bubble_interactions", [])
        if bubble_ints:
            self._kb.bubble_durations_s.append(len(bubble_ints) * 2.0)  # estimación
            self._emit_signal(LearningSignal.BUBBLE_HELD, {"interactions": len(bubble_ints)})

        # Validación cruzada — enrutar señales (20% holdout, 80% training)
        import random as _random
        _sig = {
            "incident_id": getattr(profile, "incident_id", None),
            "mine_count":  len(getattr(profile, "mine_contacts", [])),
            "actor":       str(getattr(profile, "actor_type", "UNKNOWN")),
            "techniques":  len(getattr(profile, "techniques", [])),
        }
        if _random.random() < 0.20:
            self._holdout_signals.append(_sig)
        else:
            self._train_signals.append(_sig)
        self._check_cv_divergence()

        # Aplicar ajustes automáticamente
        await self._apply_adjustments()

        logger.info(
            f"[LEARNING] Perfil ingestado — "
            f"incidente={getattr(profile, 'incident_id', 'N/A')} "
            f"total_incidentes={self._kb.incident_count}"
        )

    def _check_cv_divergence(self):
        """Detecta divergencia training/holdout — posible inyección."""
        if len(self._train_signals) < 30 or len(self._holdout_signals) < 10:
            return
        def unknown_rate(lst):
            return sum(1 for s in lst if s["actor"] == "UNKNOWN") / len(lst) if lst else 0.0
        tr = unknown_rate(self._train_signals[-50:])
        ho = unknown_rate(self._holdout_signals[-20:])
        div = abs(tr - ho)
        if div > 0.35 and not self._cv_divergence_warned:
            self._cv_divergence_warned = True
            logger.warning(
                f"[LEARNING] ALERTA validación cruzada — divergencia={div:.2f} "
                f"training={tr:.2f} holdout={ho:.2f} — posible inyección"
            )
            self._emit_signal(
                LearningSignal.TECHNIQUE_OBSERVED,
                {"technique": "CV_DIVERGENCE_DETECTED", "divergence": div},
            )
        elif div <= 0.20:
            self._cv_divergence_warned = False

    def _emit_signal(self, signal: LearningSignal, data: dict):
        """Registra una señal de aprendizaje en el historial."""
        self._signals.append({
            "signal":     signal.value,
            "data":       data,
            "timestamp":  datetime.now(timezone.utc).isoformat(),
        })

    def register_layer_pressure(self, layer: str):
        """Registra presión de escape sobre una capa específica."""
        self._kb.update_layer_pressure(layer)
        self._emit_signal(LearningSignal.LAYER_PRESSURED, {"layer": layer})

    # ── Aplicación de ajustes ─────────────────────────────────────────────────

    async def _apply_adjustments(self):
        """Calcula y distribuye ajustes a las capas conectadas."""
        adjustments = self.get_adjustments()

        # Notificar simultáneamente a todas las capas
        tasks = []

        mine_adj = adjustments.get("mines", {})
        if mine_adj:
            tasks += [self._call(cb, mine_adj) for cb in self._callbacks_mine]

        detector_adj = adjustments.get("detector", {})
        if detector_adj:
            tasks += [self._call(cb, detector_adj) for cb in self._callbacks_detector]

        bubble_adj = adjustments.get("bubble", {})
        if bubble_adj:
            tasks += [self._call(cb, bubble_adj) for cb in self._callbacks_bubble]

        if tasks:
            await asyncio.gather(*tasks)

    async def _call(self, cb: Callable, arg):
        try:
            if asyncio.iscoroutinefunction(cb):
                await cb(arg)
            else:
                cb(arg)
        except Exception as e:
            logger.warning(f"[LEARNING] Error en callback: {e}")

    # ── Exportación e importación de inteligencia ─────────────────────────────

    def export_intelligence(self) -> IntelligencePacket:
        """
        Exporta la inteligencia acumulada como paquete compartible.
        Firmado criptográficamente. Sin datos personales.
        """
        packet = IntelligencePacket(
            packet_id         = secrets.token_hex(8).upper(),
            origin_id         = self._installation_id,
            generated_at      = datetime.now(timezone.utc),
            effective_mines   = self._kb.top_mines(5),
            technique_freq    = dict(self._kb.technique_counts),
            threshold_deltas  = {
                k: v["threshold_delta"]
                for k, v in self._engine.compute_detector_adjustments(self._kb).items()
            },
            actor_distribution= self._compute_distribution(self._kb.actor_counts),
            intent_freq       = dict(self._kb.intent_counts),
        )
        packet.sign(self._signing_key)
        logger.info(
            f"[LEARNING] Inteligencia exportada — "
            f"paquete={packet.packet_id} "
            f"incidentes={self._kb.incident_count}"
        )
        return packet

    def trust_peer(self, origin_id: str, key: bytes):
        """Registra un peer de confianza con su clave de firma (PKI)."""
        self._trusted_peers[origin_id] = key
        logger.info(f"[LEARNING] Peer de confianza registrado: {origin_id}")

    def get_own_key(self) -> bytes:
        """Retorna la clave de firma de esta instalación para compartir con peers."""
        return self._signing_key

    def import_intelligence(
        self, packet: IntelligencePacket,
        signing_key: bytes = None,
        verify: bool = True
    ) -> bool:
        """
        Importa inteligencia de otra instalación AEGIS.
        Requiere que el origen esté en la lista de peers de confianza,
        o que se pase explícitamente su signing_key.
        Retorna True si se importó correctamente.
        """
        # No importar paquetes propios
        if packet.origin_id == self._installation_id:
            logger.debug("[LEARNING] Paquete propio ignorado")
            return False

        # Resolver clave de verificación: explícita > trusted_peers > rechazar
        verify_key = signing_key or self._trusted_peers.get(packet.origin_id)

        if verify and not verify_key:
            logger.warning(
                f"[LEARNING] Paquete RECHAZADO — origen no registrado: "
                f"{packet.origin_id} (paquete={packet.packet_id}). "
                f"Registra el peer con register_peer() antes de importar."
            )
            return False

        # Verificar firma
        if verify and verify_key:
            if not packet.verify(verify_key):
                logger.warning(
                    f"[LEARNING] Paquete rechazado — firma inválida: {packet.packet_id}"
                )
                return False

        # Fusionar con KB local
        for technique, count in packet.technique_freq.items():
            existing = self._kb.technique_counts.get(technique, 0)
            # Fusión conservadora: promedio ponderado (local tiene más peso)
            self._kb.technique_counts[technique] = (existing * 2 + count) // 3

        for intent, count in packet.intent_freq.items():
            existing = self._kb.intent_counts.get(intent, 0)
            self._kb.intent_counts[intent] = (existing * 2 + count) // 3

        self._imported.append({
            "packet_id":  packet.packet_id,
            "origin_id":  packet.origin_id,
            "imported_at":datetime.now(timezone.utc).isoformat(),
            "mines":      packet.effective_mines,
        })
        if len(self._imported) > self._MAX_IMPORTED:
            self._imported = self._imported[-self._MAX_IMPORTED:]

        logger.info(
            f"[LEARNING] Inteligencia importada — "
            f"origen={packet.origin_id} paquete={packet.packet_id}"
        )
        return True

    def _compute_distribution(self, counts: dict) -> dict:
        """Convierte conteos en distribución porcentual."""
        total = sum(counts.values()) or 1
        return {k: round(v / total, 3) for k, v in counts.items()}

    # ── Predicción anticipatoria — Mejora 1 ──────────────────────────────────

    def predict_next_mine(self, current_mine_type: str) -> Optional[dict]:
        """
        Dado el tipo de señuelo que acaba de tocarse, predice cuál tocará
        el atacante a continuación basándose en secuencias históricas.

        Retorna dict con predicted_mine, confidence y observations,
        o None si no hay historia suficiente (< 3 observaciones).

        Uso:
            pred = learning.predict_next_mine("MineType.FILE")
            if pred and pred["confidence"] > 0.6:
                # Preparar señuelo CREDENTIAL como el más convincente
                minefield.promote(pred["predicted_mine"])
        """
        return self._seq_tracker.predict_next(current_mine_type)

    def predict_attack_sequence(
        self, current_mine_type: str, depth: int = 3
    ) -> list:
        """
        Predice los próximos `depth` tipos de señuelo que tocará el atacante.
        Para cuando la confianza cae por debajo del 30%.

        Retorna lista de dicts [{predicted_mine, confidence}, ...].
        """
        return self._seq_tracker.predict_sequence(current_mine_type, depth)

    def get_sequence_model(self) -> dict:
        """Exporta el modelo de secuencias aprendido — para diagnóstico."""
        return self._seq_tracker.to_dict()

    # ── Ciclo de vida — Mejora 3 ──────────────────────────────────────────────

    async def start(self):
        """
        Inicia el bucle automático de sincronización con la red colectiva.
        Debe llamarse tras registrar pares con register_peer().
        """
        await self._network.start(self.export_intelligence)
        logger.info(
            f"[AEGIS.Learning] Red colectiva iniciada — "
            f"intervalo={self._network._sync_interval_s}s"
        )

    async def stop(self):
        """Detiene el bucle automático de sincronización."""
        await self._network.stop()

    # ── Red colectiva — Mejora 3 ──────────────────────────────────────────────

    def register_peer(self, peer_id: str, import_callback: Callable):
        """
        Registra una instalación par en la red colectiva.
        import_callback(packet) recibirá el IntelligencePacket en cada sync.

        En una red real, import_callback haría una llamada HTTP/gRPC a la
        instalación remota. En tests, puede ser learning_b.import_intelligence.

        Uso:
            learning_a.register_peer("AEGIS-DEU-001", learning_b.import_intelligence)
            await learning_a.start()   # sync automático cada N minutos
        """
        self._network.register_peer(peer_id, import_callback)

    def unregister_peer(self, peer_id: str):
        """Elimina un par de la red."""
        self._network.unregister_peer(peer_id)

    async def sync_now(self) -> int:
        """
        Fuerza un ciclo de sync inmediato con todos los pares.
        Útil para sincronización manual o tras un incidente crítico.
        Retorna número de pares sincronizados con éxito.
        """
        return await self._network.sync_once(self.export_intelligence)

    def get_network_status(self) -> dict:
        """Estado de la red colectiva — pares, syncs, último sync."""
        return self._network.status()

    def get_sync_log(self) -> list:
        """Historial de ciclos de sync realizados."""
        return self._network.get_sync_log()

    # ── Consultas ─────────────────────────────────────────────────────────────

    def get_adjustments(self) -> dict:
        """
        Retorna todos los ajustes calculados para aplicar a otras capas.
        """
        return {
            "mines":        self._engine.compute_mine_adjustments(self._kb),
            "detector":     self._engine.compute_detector_adjustments(self._kb),
            "bubble":       self._engine.compute_bubble_adjustments(self._kb),
            "reinforcement":self._engine.compute_layer_reinforcement(self._kb),
        }

    def get_knowledge_base(self) -> dict:
        return self._kb.to_dict()

    def get_signal_log(self) -> list:
        return list(self._signals)

    def get_imported_packets(self) -> list:
        return list(self._imported)

    def status(self) -> dict:
        net = self._network.status()
        return {
            "installation_id":   self._installation_id,
            "incidents_learned": self._kb.incident_count,
            "signals_recorded":  len(self._signals),
            "packets_imported":  len(self._imported),
            "trusted_peers":     len(self._trusted_peers),
            "cv_train_samples":  len(self._train_signals),
            "cv_holdout_samples": len(self._holdout_signals),
            "cv_divergence_warn": self._cv_divergence_warned,
            "top_mines":         self._kb.top_mines(3),
            "most_pressured":    self._kb.most_pressured_layer(),
            "avg_retention_s":   round(self._kb.avg_bubble_retention_s(), 1),
            # Mejora 3 — red colectiva
            "network": {
                "peers":           net["peers"],
                "sync_count":      net["sync_count"],
                "sync_interval_s": net["sync_interval_s"],
                "last_sync_at":    net["last_sync_at"],
                "running":         net["running"],
            },
        }
