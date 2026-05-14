"""
AEGIS — Capa 7: Análisis Forense
==================================
Estudia al intruso atrapado dentro de la burbuja.

PREGUNTAS QUE RESPONDE:
    ¿Qué es?         — ¿humano, bot, IA, script automatizado?
    ¿Cómo entró?     — vector de entrada, qué señuelo tocó primero
    ¿Qué técnicas?   — reconocimiento, fuerza bruta, enumeración, exfiltración
    ¿Qué buscaba?    — objetivo inferido de los recursos que exploró
    ¿Qué aprendemos? — patrones para Capa 8

FUENTES DE DATOS:
    ← Capa 2 (minefield):  contactos con señuelos
    ← Capa 3 (detector):   eventos de detección
    ← Capa 4 (lockdown):   snapshots de cierre
    ← Capa 6 (bubble):     interacciones dentro de la burbuja

SALIDA:
    → Capa 8 (learning):   perfil completo del intruso para aprendizaje colectivo
    → Registro persistente: historial de todos los incidentes
"""

import asyncio
import hashlib
import json
import logging
import os
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("aegis.forensic")


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class ActorType(str, Enum):
    HUMAN          = "HUMAN"           # comportamiento humano — lento, errático
    BOT_SIMPLE     = "BOT_SIMPLE"      # script básico — rápido, repetitivo
    BOT_ADVANCED   = "BOT_ADVANCED"    # bot sofisticado — adaptativo
    AI_AGENT       = "AI_AGENT"        # agente IA — sistemático, aprende
    UNKNOWN        = "UNKNOWN"         # no clasificable aún


class AttackTechnique(str, Enum):
    RECONNAISSANCE   = "RECONNAISSANCE"    # exploración sistemática
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"  # prueba de credenciales
    ENUMERATION      = "ENUMERATION"       # enumeración de recursos
    EXFILTRATION     = "EXFILTRATION"      # intento de extracción de datos
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"  # movimiento entre recursos
    PERSISTENCE      = "PERSISTENCE"       # intento de establecer permanencia
    UNKNOWN          = "UNKNOWN"


class IntentCategory(str, Enum):
    CREDENTIAL_THEFT  = "CREDENTIAL_THEFT"   # buscaba credenciales
    DATA_EXFILTRATION = "DATA_EXFILTRATION"  # buscaba datos sensibles
    SYSTEM_ACCESS     = "SYSTEM_ACCESS"      # buscaba acceso persistente
    RECONNAISSANCE    = "RECONNAISSANCE"     # solo mapeando
    UNKNOWN           = "UNKNOWN"


# ─────────────────────────────────────────────
# PERFIL DEL INTRUSO
# ─────────────────────────────────────────────

@dataclass
class IntruderProfile:
    """
    Perfil completo de un intruso construido a partir de evidencia.
    Se enriquece con cada nueva pieza de evidencia recibida.
    """
    incident_id:     str
    source_ips:      list
    first_seen:      datetime
    last_seen:       datetime

    # Clasificación
    actor_type:      ActorType         = ActorType.UNKNOWN
    techniques:      list              = field(default_factory=list)
    intent:          IntentCategory    = IntentCategory.UNKNOWN
    confidence:      float             = 0.0   # 0.0 – 1.0

    # Evidencia acumulada
    mine_contacts:   list  = field(default_factory=list)
    detection_events:list  = field(default_factory=list)
    bubble_interactions: list = field(default_factory=list)
    lockdown_snapshots:  list = field(default_factory=list)

    # Métricas de comportamiento
    total_events:        int   = 0
    unique_resources:    set   = field(default_factory=set)
    request_intervals_ms:list  = field(default_factory=list)  # tiempos entre requests
    error_rate:          float = 0.0

    # Fingerprint
    fingerprint:     str = ""

    # Score de amenaza predictivo — Mejora 4
    threat_assessment: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "incident_id":       self.incident_id,
            "source_ips":        self.source_ips,
            "first_seen":        self.first_seen.isoformat(),
            "last_seen":         self.last_seen.isoformat(),
            "actor_type":        self.actor_type.value,
            "techniques":        [t.value for t in self.techniques],
            "intent":            self.intent.value,
            "confidence":        round(self.confidence, 2),
            "total_events":      self.total_events,
            "unique_resources":  list(self.unique_resources),
            "mean_interval_ms":  round(statistics.mean(self.request_intervals_ms), 2)
                                 if self.request_intervals_ms else 0,
            "error_rate":        round(self.error_rate, 3),
            "fingerprint":       self.fingerprint,
            "mine_contacts":     len(self.mine_contacts),
            "bubble_interactions": len(self.bubble_interactions),
            "threat_assessment": self.threat_assessment,   # Mejora 4
        }


# ─────────────────────────────────────────────
# ANALIZADOR DE TIPO DE ACTOR
# ─────────────────────────────────────────────

class ActorClassifier:
    """
    Clasifica el tipo de actor basándose en patrones de comportamiento.
    Nunca por firma — siempre por métricas observables.

    CRITERIOS:
        Humano        → intervalos irregulares, errores ocasionales, exploración no lineal
        Bot simple    → intervalos regulares, sin errores, patrón repetitivo
        Bot avanzado  → intervalos variables pero rápidos, adaptativo, sistemático
        Agente IA     → sistemático, exhaustivo, adapta estrategia según respuestas
    """

    # Umbrales de clasificación
    HUMAN_MIN_INTERVAL_MS    = 500     # humano no escribe más rápido que esto
    BOT_MAX_INTERVAL_STD_MS  = 50      # bot simple tiene intervalos muy regulares
    AI_SYSTEMATIC_THRESHOLD  = 0.8    # proporción de recursos únicos vs total

    def classify(self, profile: IntruderProfile) -> tuple:
        """
        Clasifica el actor. Retorna (ActorType, confidence).
        """
        intervals = profile.request_intervals_ms
        if not intervals:
            return ActorType.UNKNOWN, 0.0

        mean_ms = statistics.mean(intervals)
        std_ms  = statistics.stdev(intervals) if len(intervals) > 1 else 0

        # Ratio de recursos únicos respecto a total de eventos
        uniqueness = (
            len(profile.unique_resources) / profile.total_events
            if profile.total_events > 0 else 0
        )

        # ── Clasificación por orden de especificidad ──────────────────────

        # Agente IA: sistemático (alta unicidad), rápido, y adapta estrategia
        if (uniqueness >= self.AI_SYSTEMATIC_THRESHOLD and
                mean_ms < 500 and
                len(profile.techniques) >= 2):
            return ActorType.AI_AGENT, min(0.9, 0.6 + uniqueness * 0.3)

        # Bot simple: muy rápido, muy regular (baja desviación estándar)
        if mean_ms < self.HUMAN_MIN_INTERVAL_MS and std_ms < self.BOT_MAX_INTERVAL_STD_MS:
            return ActorType.BOT_SIMPLE, 0.85

        # Bot avanzado: rápido pero con variabilidad introducida para evadir
        if mean_ms < self.HUMAN_MIN_INTERVAL_MS and std_ms >= self.BOT_MAX_INTERVAL_STD_MS:
            return ActorType.BOT_ADVANCED, 0.75

        # Humano: lento, irregular
        if mean_ms >= self.HUMAN_MIN_INTERVAL_MS:
            return ActorType.HUMAN, 0.70

        return ActorType.UNKNOWN, 0.3


# ─────────────────────────────────────────────
# ANALIZADOR DE TÉCNICAS
# ─────────────────────────────────────────────

class TechniqueAnalyzer:
    """
    Identifica técnicas de ataque a partir de los patrones de acceso.
    Basado en qué recursos tocó, en qué orden y con qué frecuencia.
    """

    def analyze(self, profile: IntruderProfile) -> list:
        """Retorna lista de AttackTechnique detectadas."""
        techniques = set()

        resources  = list(profile.unique_resources)
        contacts   = profile.mine_contacts
        events     = profile.detection_events

        # Reconocimiento — muchos recursos distintos explorados
        if len(resources) >= 3:
            techniques.add(AttackTechnique.RECONNAISSANCE)

        # Credential stuffing — contactó credenciales o endpoints de auth
        cred_indicators = ["credential", "auth", "login", "password", "token"]
        if any(any(ind in str(r).lower() for ind in cred_indicators)
               for r in resources):
            techniques.add(AttackTechnique.CREDENTIAL_STUFFING)

        # Enumeración — muchos puertos o rutas distintas en poco tiempo
        port_contacts = [c for c in contacts if hasattr(c, "mine_type")]
        if len(port_contacts) >= 3:
            techniques.add(AttackTechnique.ENUMERATION)

        # Exfiltración — accedió a recursos de datos o exportación
        exfil_indicators = ["database", "export", "backup", "dump", "query", "data"]
        if any(any(ind in str(r).lower() for ind in exfil_indicators)
               for r in resources):
            techniques.add(AttackTechnique.EXFILTRATION)

        # Movimiento lateral — múltiples IPs involucradas
        if len(profile.source_ips) > 1:
            techniques.add(AttackTechnique.LATERAL_MOVEMENT)

        # Persistencia — intentó acceder a configuración o claves
        persist_indicators = ["key", "cert", "ssh", "config", "secret"]
        if any(any(ind in str(r).lower() for ind in persist_indicators)
               for r in resources):
            techniques.add(AttackTechnique.PERSISTENCE)

        return list(techniques) if techniques else [AttackTechnique.UNKNOWN]


# ─────────────────────────────────────────────
# ANALIZADOR DE INTENCIÓN
# ─────────────────────────────────────────────

class IntentAnalyzer:
    """
    Infiere el objetivo del intruso a partir de lo que buscaba.
    No lo que dijo — lo que hizo.
    """

    def analyze(self, profile: IntruderProfile) -> IntentCategory:
        resources  = [str(r).lower() for r in profile.unique_resources]
        techniques = profile.techniques

        # Robo de credenciales — tocó credenciales, tokens, auth
        cred_score = sum(1 for r in resources
                         if any(k in r for k in
                                ["credential", "password", "token", "key", "auth", "login"]))

        # Exfiltración de datos — tocó bases de datos, exports, backups
        data_score = sum(1 for r in resources
                         if any(k in r for k in
                                ["database", "backup", "export", "query", "data", "table"]))

        # Acceso al sistema — tocó configs, SSH, servicios de administración
        system_score = sum(1 for r in resources
                           if any(k in r for k in
                                  ["config", "ssh", "admin", "shell", "service", "secret"]))

        # Solo reconocimiento — exploró mucho pero no profundizó
        recon_only = (AttackTechnique.RECONNAISSANCE in techniques and
                      len(techniques) == 1)

        # Decidir por mayor puntuación
        scores = {
            IntentCategory.CREDENTIAL_THEFT:  cred_score,
            IntentCategory.DATA_EXFILTRATION:  data_score,
            IntentCategory.SYSTEM_ACCESS:      system_score,
        }
        if recon_only:
            return IntentCategory.RECONNAISSANCE

        best = max(scores, key=scores.get)
        return best if scores[best] > 0 else IntentCategory.UNKNOWN


# ─────────────────────────────────────────────
# MOTOR FORENSE PRINCIPAL
# ─────────────────────────────────────────────

class ThreatScorer:
    """
    Mejora 4 — Perfil de amenaza predictivo.

    Genera un score de peligrosidad [0.0–1.0] combinando:
        - Técnicas usadas          → las más peligrosas pesan más
        - Tiempo en sistema        → más tiempo = mayor amenaza acumulada
        - Recursos tocados         → amplitud del reconocimiento
        - Tipo de actor            → AI_AGENT > BOT_ADVANCED > HUMAN > BOT_SIMPLE
        - Contactos de señuelo     → intención activa confirmada

    El score predice si el intruso escalará:
        < 0.30  → BAJO     — sondeo superficial, probablemente se irá
        0.30–0.59 → MEDIO  — reconocimiento activo, puede persistir
        0.60–0.79 → ALTO   — amenaza real, escalada probable
        ≥ 0.80  → CRÍTICO  — escalada inminente, requiere acción inmediata

    DISEÑO DE PESOS:
        Cada dimensión contribuye con un peso normalizado.
        La suma de pesos máximos = 1.0.
        El score final es la suma ponderada de contribuciones normalizadas.
    """

    # Peso de cada dimensión — suma = 1.0
    W_ACTOR      = 0.25   # quién es
    W_TECHNIQUES = 0.30   # qué hace
    W_RESOURCES  = 0.20   # cuánto ha visto
    W_TIME       = 0.15   # cuánto lleva
    W_MINES      = 0.10   # confirmación de intención

    # Peligrosidad por tipo de actor [0.0–1.0]
    ACTOR_DANGER = {
        ActorType.BOT_SIMPLE:   0.30,
        ActorType.BOT_ADVANCED: 0.65,
        ActorType.HUMAN:        0.55,
        ActorType.AI_AGENT:     0.90,
        ActorType.UNKNOWN:      0.40,
    }

    # Peligrosidad por técnica [0.0–1.0]
    TECHNIQUE_DANGER = {
        AttackTechnique.RECONNAISSANCE:      0.40,
        AttackTechnique.ENUMERATION:         0.50,
        AttackTechnique.CREDENTIAL_STUFFING: 0.75,
        AttackTechnique.LATERAL_MOVEMENT:    0.85,
        AttackTechnique.EXFILTRATION:        0.90,
        AttackTechnique.PERSISTENCE:         0.95,
        AttackTechnique.UNKNOWN:             0.20,
    }

    # Umbrales de tiempo en sistema
    TIME_THRESHOLDS = [
        (30,   0.10),    # < 30s  → trivial
        (120,  0.30),    # < 2min → sondeo rápido
        (300,  0.60),    # < 5min → reconocimiento activo
        (900,  0.85),    # < 15min → sesión prolongada
        (float("inf"), 1.00),  # ≥ 15min → muy peligroso
    ]

    # Umbrales de recursos únicos tocados
    RESOURCE_THRESHOLDS = [
        (2,  0.15),
        (5,  0.40),
        (10, 0.65),
        (20, 0.85),
        (float("inf"), 1.00),
    ]

    def score(self, profile: "IntruderProfile") -> dict:
        """
        Calcula el score de peligrosidad del perfil.

        Retorna dict con:
            score:        float  — peligrosidad global [0.0–1.0]
            level:        str    — BAJO / MEDIO / ALTO / CRÍTICO
            will_escalate:bool   — predicción de escalada
            breakdown:    dict   — contribución de cada dimensión
            recommendation: str — acción sugerida
        """
        # ── Dimensión 1: Actor ────────────────────────────────────────────────
        d_actor = self.ACTOR_DANGER.get(profile.actor_type, 0.40)

        # ── Dimensión 2: Técnicas ─────────────────────────────────────────────
        if profile.techniques:
            dangers = [
                self.TECHNIQUE_DANGER.get(t, 0.20)
                for t in profile.techniques
            ]
            # Peso al máximo y la media — una técnica muy peligrosa domina
            d_tech = 0.6 * max(dangers) + 0.4 * (sum(dangers) / len(dangers))
        else:
            d_tech = 0.10

        # ── Dimensión 3: Recursos ─────────────────────────────────────────────
        n_resources = len(profile.unique_resources) + len(profile.mine_contacts)
        d_resources = self._threshold_score(n_resources, self.RESOURCE_THRESHOLDS)

        # ── Dimensión 4: Tiempo en sistema ────────────────────────────────────
        elapsed_s = (profile.last_seen - profile.first_seen).total_seconds()
        d_time    = self._threshold_score(elapsed_s, self.TIME_THRESHOLDS)

        # ── Dimensión 5: Confirmación de intención (señuelos tocados) ─────────
        n_mines = len(profile.mine_contacts)
        if n_mines == 0:
            d_mines = 0.0
        elif n_mines == 1:
            d_mines = 0.50   # un señuelo = intención confirmada
        elif n_mines <= 3:
            d_mines = 0.75
        else:
            d_mines = 1.00   # múltiples señuelos = máxima intención

        # ── Score global ponderado ────────────────────────────────────────────
        score = (
            self.W_ACTOR      * d_actor      +
            self.W_TECHNIQUES * d_tech       +
            self.W_RESOURCES  * d_resources  +
            self.W_TIME       * d_time       +
            self.W_MINES      * d_mines
        )
        score = round(min(1.0, max(0.0, score)), 3)

        # ── Nivel y predicción ────────────────────────────────────────────────
        level, will_escalate, recommendation = self._classify(score, profile)

        return {
            "score":          score,
            "level":          level,
            "will_escalate":  will_escalate,
            "recommendation": recommendation,
            "breakdown": {
                "actor":      round(d_actor,     3),
                "techniques": round(d_tech,      3),
                "resources":  round(d_resources, 3),
                "time":       round(d_time,      3),
                "mines":      round(d_mines,     3),
            },
            "inputs": {
                "actor_type":    profile.actor_type.value,
                "techniques":    [t.value for t in profile.techniques],
                "n_resources":   n_resources,
                "elapsed_s":     round(elapsed_s, 1),
                "n_mines":       n_mines,
            },
        }

    @staticmethod
    def _threshold_score(value: float, thresholds: list) -> float:
        """Convierte un valor numérico en score según umbrales ordenados."""
        for limit, score in thresholds:
            if value < limit:
                return score
        return thresholds[-1][1]

    @staticmethod
    def _classify(score: float, profile: "IntruderProfile") -> tuple:
        """Clasifica el score en nivel, predicción y recomendación."""
        # Señales adicionales que fuerzan escalada independiente del score
        has_lateral    = AttackTechnique.LATERAL_MOVEMENT in profile.techniques
        has_persistence = AttackTechnique.PERSISTENCE     in profile.techniques
        has_exfil      = AttackTechnique.EXFILTRATION     in profile.techniques
        force_escalate = has_lateral or has_persistence or has_exfil

        if score >= 0.80 or force_escalate:
            return (
                "CRÍTICO",
                True,
                "LOCKDOWN_INMEDIATO — escalada inminente detectada",
            )
        elif score >= 0.60:
            return (
                "ALTO",
                True,
                "JUMP_PREVENTIVO — alta probabilidad de escalada",
            )
        elif score >= 0.30:
            return (
                "MEDIO",
                False,
                "MONITORIZAR — reconocimiento activo, sin escalada inmediata",
            )
        else:
            return (
                "BAJO",
                False,
                "OBSERVAR — sondeo superficial, escalada improbable",
            )


# ─────────────────────────────────────────────
# MOTOR FORENSE — orquesta todos los analizadores
# ─────────────────────────────────────────────

class ForensicEngine:
    """
    Motor forense — construye y enriquece perfiles de intrusos
    a medida que llega evidencia de todas las capas.
    """

    def __init__(self):
        self._actor_classifier  = ActorClassifier()
        self._technique_analyzer= TechniqueAnalyzer()
        self._intent_analyzer   = IntentAnalyzer()
        self._threat_scorer     = ThreatScorer()     # Mejora 4
        self._last_event_time:  dict = {}   # ip → timestamp

    def ingest_mine_contact(self, profile: IntruderProfile, contact) -> None:
        """Procesa un contacto con señuelo de Capa 2."""
        profile.mine_contacts.append(contact)
        profile.total_events += 1

        resource = getattr(contact, "mine_name", str(contact))
        profile.unique_resources.add(resource)
        self._update_intervals(profile, contact.source_ip)

        logger.debug(
            f"[FORENSIC] Mine contact ingestado — "
            f"incident={profile.incident_id} resource={resource}"
        )

    def ingest_detection_event(self, profile: IntruderProfile, event) -> None:
        """Procesa un evento de detección de Capa 3."""
        profile.detection_events.append(event)
        profile.total_events += 1

        for indicator in getattr(event, "indicators", []):
            profile.unique_resources.add(str(indicator)[:50])

        for ip in getattr(event, "source_ips", []):
            self._update_intervals(profile, ip)
            if ip not in profile.source_ips:
                profile.source_ips.append(ip)

    def ingest_bubble_interaction(self, profile: IntruderProfile, interaction) -> None:
        """Procesa una interacción de Capa 6 (dentro de la burbuja)."""
        profile.bubble_interactions.append(interaction)
        profile.total_events += 1

        resource = getattr(interaction, "interaction_type", "unknown")
        profile.unique_resources.add(str(resource))

        ip = getattr(interaction, "session_id", "unknown")
        self._update_intervals(profile, ip)

    def ingest_lockdown_snapshot(self, profile: IntruderProfile, snapshot: dict) -> None:
        """Procesa un snapshot de cierre de Capa 4."""
        profile.lockdown_snapshots.append(snapshot)
        profile.total_events += 1

    def _update_intervals(self, profile: IntruderProfile, ip: str):
        """Actualiza los intervalos entre eventos para clasificación de actor."""
        now  = time.monotonic() * 1000   # ms
        last = self._last_event_time.get(ip)
        if last is not None:
            interval = now - last
            profile.request_intervals_ms.append(interval)
        self._last_event_time[ip] = now
        profile.last_seen = datetime.now(timezone.utc)

    def analyze(self, profile: IntruderProfile) -> IntruderProfile:
        """
        Ejecuta el análisis completo sobre el perfil acumulado.
        Actualiza actor_type, techniques, intent, confidence y threat_score.
        """
        # Clasificar actor
        actor, confidence = self._actor_classifier.classify(profile)
        profile.actor_type  = actor
        profile.confidence  = confidence

        # Identificar técnicas
        profile.techniques = self._technique_analyzer.analyze(profile)

        # Inferir intención
        profile.intent = self._intent_analyzer.analyze(profile)

        # Calcular fingerprint del perfil completo
        fp_data = (
            "|".join(sorted(profile.source_ips)) +
            "|" + actor.value +
            "|" + "|".join(sorted(str(t) for t in profile.techniques))
        )
        profile.fingerprint = hashlib.sha256(fp_data.encode()).hexdigest()[:16]

        # Calcular score de amenaza predictivo — Mejora 4
        profile.threat_assessment = self._threat_scorer.score(profile)

        logger.info(
            f"[FORENSIC] Análisis completado — "
            f"incident={profile.incident_id} "
            f"actor={actor.value} "
            f"confianza={confidence:.2f} "
            f"técnicas={len(profile.techniques)} "
            f"intención={profile.intent.value} "
            f"amenaza={profile.threat_assessment['level']} "
            f"({profile.threat_assessment['score']:.2f}) "
            f"escalada={'SÍ' if profile.threat_assessment['will_escalate'] else 'NO'}"
        )
        return profile


# ─────────────────────────────────────────────
# FACHADA PRINCIPAL — AegisForensic
# ─────────────────────────────────────────────

class AegisForensic:
    """
    Fachada de Capa 7 — Análisis Forense.

    Uso:
        forensic = AegisForensic()
        forensic.register_learning_callback(learning.ingest_profile)

        # Conectar como callback de otras capas:
        minefield.register_forensic_callback(forensic.on_mine_contact)
        detector.register_forensic_callback(forensic.on_detection_event)
        bubble.register_forensic_callback(forensic.on_bubble_interaction)
        lockdown.register_forensic_callback(forensic.on_lockdown_snapshot)

        # Abrir incidente cuando se detecta intruso:
        incident_id = forensic.open_incident(["1.2.3.4"])

        # Analizar en cualquier momento:
        profile = forensic.analyze(incident_id)

        # Cerrar cuando termina:
        forensic.close_incident(incident_id)
    """

    def __init__(self, persistence=None):
        self._engine    = ForensicEngine()
        self._incidents: dict = {}   # incident_id → IntruderProfile
        self._closed:    dict = {}   # incident_id → IntruderProfile (cerrados)

        self._callbacks_learning: list = []   # → Capa 8
        self._persistence = persistence        # CheckpointManager opcional

        # Directorio de incidentes independiente (fallback sin persistence)
        if persistence:
            self._incidents_dir = persistence.incidents_dir
        else:
            self._incidents_dir = Path("state/incidents")
            self._incidents_dir.mkdir(parents=True, exist_ok=True)

        logger.info("[AEGIS.Forensic] Capa 7 inicializada — motor forense listo")

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def register_learning_callback(self, cb: Callable):
        """Capa 8 — recibe el perfil completo al cerrar un incidente."""
        self._callbacks_learning.append(cb)

    # ── Gestión de incidentes ─────────────────────────────────────────────────

    def open_incident(self, source_ips: list) -> str:
        """
        Abre un nuevo incidente forense.
        Retorna incident_id único.
        """
        import secrets as _sec
        incident_id = _sec.token_hex(6).upper()
        profile     = IntruderProfile(
            incident_id = incident_id,
            source_ips  = list(source_ips),
            first_seen  = datetime.now(timezone.utc),
            last_seen   = datetime.now(timezone.utc),
        )
        self._incidents[incident_id] = profile
        logger.info(
            f"[FORENSIC] Incidente abierto — "
            f"id={incident_id} ips={source_ips}"
        )
        return incident_id

    def close_incident(self, incident_id: str) -> Optional[IntruderProfile]:
        """
        Cierra un incidente — ejecuta análisis final y notifica Capa 8.
        """
        profile = self._incidents.pop(incident_id, None)
        if not profile:
            return None

        # Análisis final antes de cerrar
        profile = self._engine.analyze(profile)
        self._closed[incident_id] = profile
        self._persist_incident(incident_id, profile)

        logger.info(
            f"[FORENSIC] Incidente cerrado — "
            f"id={incident_id} "
            f"actor={profile.actor_type.value} "
            f"intención={profile.intent.value} "
            f"técnicas={[t.value for t in profile.techniques]}"
        )

        # Notificar Capa 8 de forma asíncrona si hay event loop activo
        if self._callbacks_learning:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self._notify_learning(profile))
                else:
                    loop.run_until_complete(self._notify_learning(profile))
            except RuntimeError:
                # Sin event loop — llamar sincrónicamente
                for cb in self._callbacks_learning:
                    try:
                        if not asyncio.iscoroutinefunction(cb):
                            cb(profile)
                    except Exception as e:
                        logger.warning(f"[FORENSIC] Error en callback: {e}")

        return profile

    async def close_incident_async(self, incident_id: str) -> Optional[IntruderProfile]:
        """Versión async de close_incident — para uso dentro de event loops."""
        profile = self._incidents.pop(incident_id, None)
        if not profile:
            return None

        profile = self._engine.analyze(profile)
        self._closed[incident_id] = profile
        self._persist_incident(incident_id, profile)

        await self._notify_learning(profile)
        return profile

    def _persist_incident(self, incident_id: str, profile: 'IntruderProfile'):
        """Escribe el perfil del incidente a disco con fsync."""
        if self._persistence:
            self._persistence.save_incident(incident_id, profile.to_dict())
            return
        # Fallback sin CheckpointManager
        from datetime import timezone
        path = self._incidents_dir / f"incident_{incident_id}.jsonl"
        try:
            import json as _json
            with open(path, "a", encoding="utf-8") as f:
                line = _json.dumps(
                    {"ts": __import__('datetime').datetime.now(timezone.utc).isoformat(),
                     "incident": incident_id, "data": profile.to_dict()},
                    ensure_ascii=False, default=str,
                )
                f.write(line + "\n")
                f.flush()
                os.fsync(f.fileno())
        except OSError as e:
            logger.warning(f"[FORENSIC] Error escribiendo incidente a disco: {e}")

    async def _notify_learning(self, profile: IntruderProfile):
        """Notifica a Capa 8 con el perfil completo."""
        for cb in self._callbacks_learning:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(profile)
                else:
                    cb(profile)
            except Exception as e:
                logger.warning(f"[FORENSIC] Error notificando Capa 8: {e}")

    # ── Callbacks de ingesta desde otras capas ────────────────────────────────

    async def on_mine_contact(self, contact):
        """Capa 2 — contacto con señuelo."""
        ip      = getattr(contact, "source_ip", "unknown")
        profile = self._find_or_create_incident([ip])
        self._engine.ingest_mine_contact(profile, contact)

    async def on_detection_event(self, event):
        """Capa 3 — evento de detección."""
        ips     = getattr(event, "source_ips", ["unknown"])
        profile = self._find_or_create_incident(ips)
        self._engine.ingest_detection_event(profile, event)

    async def on_bubble_interaction(self, interaction):
        """Capa 6 — interacción dentro de la burbuja."""
        if not self._incidents:
            return
        # Asignar a incidente activo más reciente
        profile = list(self._incidents.values())[-1]
        self._engine.ingest_bubble_interaction(profile, interaction)

    async def on_lockdown_snapshot(self, snapshot: dict):
        """Capa 4 — snapshot de cierre."""
        if not self._incidents:
            return
        profile = list(self._incidents.values())[-1]
        self._engine.ingest_lockdown_snapshot(profile, snapshot)

    def _find_or_create_incident(self, ips: list) -> IntruderProfile:
        """Busca incidente activo para las IPs dadas o crea uno nuevo."""
        for profile in self._incidents.values():
            if any(ip in profile.source_ips for ip in ips):
                return profile
        incident_id = self.open_incident(ips)
        return self._incidents[incident_id]

    # ── Análisis ──────────────────────────────────────────────────────────────

    def analyze(self, incident_id: str) -> Optional[IntruderProfile]:
        """Ejecuta análisis sobre un incidente activo — sin cerrarlo."""
        profile = self._incidents.get(incident_id)
        if not profile:
            return None
        return self._engine.analyze(profile)

    def score_threat(self, incident_id: str) -> Optional[dict]:
        """
        Mejora 4 — Calcula el score de amenaza predictivo para un incidente.
        Puede llamarse en cualquier momento sin cerrar el incidente.
        Retorna dict con score, level, will_escalate y breakdown.
        Retorna None si el incidente no existe.
        """
        profile = self._incidents.get(incident_id) or \
                  self._closed.get(incident_id)
        if not profile:
            return None
        return self._engine._threat_scorer.score(profile)

    # ── Consultas ─────────────────────────────────────────────────────────────

    def get_profile(self, incident_id: str) -> Optional[dict]:
        p = self._incidents.get(incident_id) or self._closed.get(incident_id)
        return p.to_dict() if p else None

    def get_all_profiles(self) -> list:
        all_p = list(self._incidents.values()) + list(self._closed.values())
        return [p.to_dict() for p in all_p]

    def active_incidents(self) -> int:
        return len(self._incidents)

    def closed_incidents(self) -> int:
        return len(self._closed)

    def status(self) -> dict:
        return {
            "active_incidents":  self.active_incidents(),
            "closed_incidents":  self.closed_incidents(),
            "total_incidents":   self.active_incidents() + self.closed_incidents(),
            "incidents_on_disk": len(list(self._incidents_dir.glob("*.jsonl"))),
        }
