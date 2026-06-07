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
    HUMAN          = "HUMAN"
    BOT_SIMPLE     = "BOT_SIMPLE"
    BOT_ADVANCED   = "BOT_ADVANCED"
    AI_AGENT       = "AI_AGENT"
    UNKNOWN        = "UNKNOWN"


class AttackTechnique(str, Enum):
    RECONNAISSANCE      = "RECONNAISSANCE"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    ENUMERATION         = "ENUMERATION"
    EXFILTRATION        = "EXFILTRATION"
    LATERAL_MOVEMENT    = "LATERAL_MOVEMENT"
    PERSISTENCE         = "PERSISTENCE"
    UNKNOWN             = "UNKNOWN"


class IntentCategory(str, Enum):
    CREDENTIAL_THEFT  = "CREDENTIAL_THEFT"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SYSTEM_ACCESS     = "SYSTEM_ACCESS"
    RECONNAISSANCE    = "RECONNAISSANCE"
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

    actor_type:      ActorType         = ActorType.UNKNOWN
    techniques:      list              = field(default_factory=list)
    intent:          IntentCategory    = IntentCategory.UNKNOWN
    confidence:      float             = 0.0

    mine_contacts:       list  = field(default_factory=list)
    detection_events:    list  = field(default_factory=list)
    bubble_interactions: list  = field(default_factory=list)
    lockdown_snapshots:  list  = field(default_factory=list)

    total_events:         int   = 0
    unique_resources:     set   = field(default_factory=set)
    request_intervals_ms: list  = field(default_factory=list)
    error_rate:           float = 0.0

    fingerprint:       str  = ""
    threat_assessment: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """
        Serializes the intruder profile to a JSON-compatible dictionary.

        Returns:
            dict: A dictionary representation of the profile with all fields
                serialized to JSON-safe types. Sets are converted to lists,
                datetimes to ISO-format strings, and enums to their string values.
        """
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
            "threat_assessment": self.threat_assessment,
        }


# ─────────────────────────────────────────────
# ANALIZADOR DE TIPO DE ACTOR
# ─────────────────────────────────────────────

class ActorClassifier:
    """
    Clasifica el tipo de actor basándose en patrones de comportamiento.
    Nunca por firma — siempre por métricas observables.
    """

    HUMAN_MIN_INTERVAL_MS    = 500
    BOT_MAX_INTERVAL_STD_MS  = 50
    AI_SYSTEMATIC_THRESHOLD  = 0.8

    def classify(self, profile: IntruderProfile) -> tuple:
        """
        Classifies the intruder actor type based on behavioral metrics.

        Uses request timing intervals, resource uniqueness ratio, and
        technique diversity to distinguish between human operators,
        simple bots, advanced bots, and AI agents.

        Args:
            profile: The intruder profile containing behavioral metrics
                such as request intervals, unique resources, and techniques.

        Returns:
            tuple: A (ActorType, confidence) pair where confidence is a
                float in [0.0, 1.0] indicating classification certainty.
                Returns (ActorType.UNKNOWN, 0.0) if no interval data exists.
        """
        intervals = profile.request_intervals_ms
        if not intervals:
            return ActorType.UNKNOWN, 0.0

        mean_ms = statistics.mean(intervals)
        std_ms  = statistics.stdev(intervals) if len(intervals) > 1 else 0

        uniqueness = (
            len(profile.unique_resources) / profile.total_events
            if profile.total_events > 0 else 0
        )

        if (uniqueness >= self.AI_SYSTEMATIC_THRESHOLD and
                mean_ms < 500 and
                len(profile.techniques) >= 2):
            return ActorType.AI_AGENT, min(0.9, 0.6 + uniqueness * 0.3)

        if mean_ms < self.HUMAN_MIN_INTERVAL_MS and std_ms < self.BOT_MAX_INTERVAL_STD_MS:
            return ActorType.BOT_SIMPLE, 0.85

        if mean_ms < self.HUMAN_MIN_INTERVAL_MS and std_ms >= self.BOT_MAX_INTERVAL_STD_MS:
            return ActorType.BOT_ADVANCED, 0.75

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
        """
        Identifies attack techniques used based on resource access patterns.

        Inspects the resources touched, mine contacts, and detection events
        to infer which attack techniques were employed. Detection is
        keyword-based and relies solely on observable behavior.

        Args:
            profile: The intruder profile containing accumulated evidence
                including unique resources, mine contacts, and detection events.

        Returns:
            list: A list of AttackTechnique values detected in the profile.
                Returns [AttackTechnique.UNKNOWN] if no techniques are identified.
        """
        techniques = set()

        resources  = list(profile.unique_resources)
        contacts   = profile.mine_contacts
        events     = profile.detection_events

        if len(resources) >= 3:
            techniques.add(AttackTechnique.RECONNAISSANCE)

        cred_indicators = ["credential", "auth", "login", "password", "token"]
        if any(any(ind in str(r).lower() for ind in cred_indicators)
               for r in resources):
            techniques.add(AttackTechnique.CREDENTIAL_STUFFING)

        port_contacts = [c for c in contacts if hasattr(c, "mine_type")]
        if len(port_contacts) >= 3:
            techniques.add(AttackTechnique.ENUMERATION)

        exfil_indicators = ["database", "export", "backup", "dump", "query", "data"]
        if any(any(ind in str(r).lower() for ind in exfil_indicators)
               for r in resources):
            techniques.add(AttackTechnique.EXFILTRATION)

        if len(profile.source_ips) > 1:
            techniques.add(AttackTechnique.LATERAL_MOVEMENT)

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
        """
        Infers the intruder's primary objective from resource access patterns.

        Scores each intent category by counting how many accessed resources
        match category-specific keywords. The highest-scoring category wins.
        Returns IntentCategory.RECONNAISSANCE if only reconnaissance technique
        was detected, and IntentCategory.UNKNOWN if no keywords matched.

        Args:
            profile: The intruder profile containing unique resources and
                identified attack techniques.

        Returns:
            IntentCategory: The inferred primary intent of the intruder.
        """
        resources  = [str(r).lower() for r in profile.unique_resources]
        techniques = profile.techniques

        cred_score = sum(1 for r in resources
                         if any(k in r for k in
                                ["credential", "password", "token", "key", "auth", "login"]))

        data_score = sum(1 for r in resources
                         if any(k in r for k in
                                ["database", "backup", "export", "query", "data", "table"]))

        system_score = sum(1 for r in resources
                           if any(k in r for k in
                                  ["config", "ssh", "admin", "shell", "service", "secret"]))

        recon_only = (AttackTechnique.RECONNAISSANCE in techniques and
                      len(techniques) == 1)

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
        - Técnicas usadas
        - Tiempo en sistema
        - Recursos tocados
        - Tipo de actor
        - Contactos de señuelo
    """

    W_ACTOR      = 0.25
    W_TECHNIQUES = 0.30
    W_RESOURCES  = 0.20
    W_TIME       = 0.15
    W_MINES      = 0.10

    ACTOR_DANGER = {
        ActorType.BOT_SIMPLE:   0.30,
        ActorType.BOT_ADVANCED: 0.65,
        ActorType.HUMAN:        0.55,
        ActorType.AI_AGENT:     0.90,
        ActorType.UNKNOWN:      0.40,
    }

    TECHNIQUE_DANGER = {
        AttackTechnique.RECONNAISSANCE:      0.40,
        AttackTechnique.ENUMERATION:         0.50,
        AttackTechnique.CREDENTIAL_STUFFING: 0.75,
        AttackTechnique.LATERAL_MOVEMENT:    0.85,
        AttackTechnique.EXFILTRATION:        0.90,
        AttackTechnique.PERSISTENCE:         0.95,
        AttackTechnique.UNKNOWN:             0.20,
    }

    TIME_THRESHOLDS = [
        (30,   0.10),
        (120,  0.30),
        (300,  0.60),
        (900,  0.85),
        (float("inf"), 1.00),
    ]

    RESOURCE_THRESHOLDS = [
        (2,  0.15),
        (5,  0.40),
        (10, 0.65),
        (20, 0.85),
        (float("inf"), 1.00),
    ]

    def score(self, profile: "IntruderProfile") -> dict:
        """
        Calculates a predictive danger score for the given intruder profile.

        Combines five weighted dimensions — actor type, attack techniques,
        resources touched, time in system, and mine contacts — into a single
        danger score. Each dimension is normalized to [0.0, 1.0] before weighting.

        Args:
            profile: The intruder profile to score. Must have actor_type,
                techniques, unique_resources, mine_contacts, first_seen,
                and last_seen populated for accurate results.

        Returns:
            dict: A dictionary containing:
                - score (float): Global danger score in [0.0, 1.0].
                - level (str): One of BAJO, MEDIO, ALTO, or CRÍTICO.
                - will_escalate (bool): Predicted escalation likelihood.
                - recommendation (str): Suggested defensive action.
                - breakdown (dict): Per-dimension contribution scores.
                - inputs (dict): Raw input values used for scoring.
        """
        d_actor = self.ACTOR_DANGER.get(profile.actor_type, 0.40)

        if profile.techniques:
            dangers = [
                self.TECHNIQUE_DANGER.get(t, 0.20)
                for t in profile.techniques
            ]
            d_tech = 0.6 * max(dangers) + 0.4 * (sum(dangers) / len(dangers))
        else:
            d_tech = 0.10

        n_resources = len(profile.unique_resources) + len(profile.mine_contacts)
        d_resources = self._threshold_score(n_resources, self.RESOURCE_THRESHOLDS)

        elapsed_s = (profile.last_seen - profile.first_seen).total_seconds()
        d_time    = self._threshold_score(elapsed_s, self.TIME_THRESHOLDS)

        n_mines = len(profile.mine_contacts)
        if n_mines == 0:
            d_mines = 0.0
        elif n_mines == 1:
            d_mines = 0.50
        elif n_mines <= 3:
            d_mines = 0.75
        else:
            d_mines = 1.00

        score = (
            self.W_ACTOR      * d_actor      +
            self.W_TECHNIQUES * d_tech       +
            self.W_RESOURCES  * d_resources  +
            self.W_TIME       * d_time       +
            self.W_MINES      * d_mines
        )
        score = round(min(1.0, max(0.0, score)), 3)

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
        """
        Maps a numeric value to a score using ordered threshold brackets.

        Iterates through thresholds in ascending order and returns the score
        associated with the first bracket whose limit exceeds the value.

        Args:
            value: The numeric value to map, such as elapsed seconds or
                resource count.
            thresholds: An ordered list of (limit, score) tuples where
                limit is the upper bound (exclusive) for the bracket.

        Returns:
            float: The score associated with the matching threshold bracket.
        """
        for limit, score in thresholds:
            if value < limit:
                return score
        return thresholds[-1][1]

    @staticmethod
    def _classify(score: float, profile: "IntruderProfile") -> tuple:
        """
        Maps a danger score to a threat level, escalation prediction, and recommendation.

        Certain high-severity techniques (lateral movement, persistence,
        exfiltration) force a CRÍTICO classification regardless of the
        numeric score.

        Args:
            score: The computed danger score in [0.0, 1.0].
            profile: The intruder profile used to check for force-escalate
                techniques.

        Returns:
            tuple: A (level, will_escalate, recommendation) triple where
                level is a string (BAJO/MEDIO/ALTO/CRÍTICO),
                will_escalate is a bool, and recommendation is an action string.
        """
        has_lateral     = AttackTechnique.LATERAL_MOVEMENT in profile.techniques
        has_persistence = AttackTechnique.PERSISTENCE      in profile.techniques
        has_exfil       = AttackTechnique.EXFILTRATION     in profile.techniques
        force_escalate  = has_lateral or has_persistence or has_exfil

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
        self._actor_classifier   = ActorClassifier()
        self._technique_analyzer = TechniqueAnalyzer()
        self._intent_analyzer    = IntentAnalyzer()
        self._threat_scorer      = ThreatScorer()
        self._last_event_time:   dict = {}

    def ingest_mine_contact(self, profile: IntruderProfile, contact) -> None:
        """
        Ingests a honeypot contact event from Layer 2 (minefield) into the profile.

        Records the contact, increments the event counter, adds the touched
        resource to the unique resources set, and updates request intervals
        for actor classification.

        Args:
            profile: The active intruder profile to enrich with this contact.
            contact: A mine contact object with at least a ``source_ip``
                attribute and optionally a ``mine_name`` attribute identifying
                the honeypot resource that was touched.
        """
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
        """
        Ingests a detection event from Layer 3 (detector) into the profile.

        Appends the event, increments the event counter, adds all indicators
        to the unique resources set, and updates source IPs and request
        intervals from the event's source IP list.

        Args:
            profile: The active intruder profile to enrich with this event.
            event: A detection event object with optional ``indicators``
                (iterable of resource indicators) and ``source_ips``
                (list of originating IP addresses) attributes.
        """
        profile.detection_events.append(event)
        profile.total_events += 1

        for indicator in getattr(event, "indicators", []):
            profile.unique_resources.add(str(indicator)[:50])

        for ip in getattr(event, "source_ips", []):
            self._update_intervals(profile, ip)
            if ip not in profile.source_ips:
                profile.source_ips.append(ip)

    def ingest_bubble_interaction(self, profile: IntruderProfile, interaction) -> None:
        """
        Ingests an interaction from Layer 6 (bubble) into the profile.

        Records the interaction, increments the event counter, adds the
        interaction type as a unique resource, and updates request intervals
        using the interaction's session ID as the IP key.

        Args:
            profile: The active intruder profile to enrich with this interaction.
            interaction: A bubble interaction object with optional
                ``interaction_type`` (str) and ``session_id`` (str) attributes.
        """
        profile.bubble_interactions.append(interaction)
        profile.total_events += 1

        resource = getattr(interaction, "interaction_type", "unknown")
        profile.unique_resources.add(str(resource))

        ip = getattr(interaction, "session_id", "unknown")
        self._update_intervals(profile, ip)

    def ingest_lockdown_snapshot(self, profile: IntruderProfile, snapshot: dict) -> None:
        """
        Ingests a lockdown snapshot from Layer 4 into the profile.

        Appends the snapshot dictionary to the profile's lockdown history
        and increments the total event counter.

        Args:
            profile: The active intruder profile to enrich with this snapshot.
            snapshot: A dictionary containing the lockdown state captured
                by Layer 4 at the time of system closure.
        """
        profile.lockdown_snapshots.append(snapshot)
        profile.total_events += 1

    def _update_intervals(self, profile: IntruderProfile, ip: str) -> None:
        """Actualiza los intervalos entre eventos para clasificación de actor."""
        now  = time.monotonic() * 1000
        last = self._last_event_time.get(ip)
        if last is not None:
            interval = now - last
            profile.request_intervals_ms.append(interval)
        self._last_event_time[ip] = now
        profile.last_seen = datetime.now(timezone.utc)

    def analyze(self, profile: IntruderProfile) -> IntruderProfile:
        """
        Runs a full forensic analysis pass over the accumulated profile.

        Classifies the actor type, identifies attack techniques, infers
        intent, computes a SHA-256 fingerprint, and calculates the
        predictive threat assessment. Updates the profile in place and
        returns it.

        Args:
            profile: The intruder profile to analyze. Must have accumulated
                at least some evidence via the ingest_* methods for
                meaningful results.

        Returns:
            IntruderProfile: The same profile object with actor_type,
                confidence, techniques, intent, fingerprint, and
                threat_assessment fields updated.
        """
        actor, confidence = self._actor_classifier.classify(profile)
        profile.actor_type  = actor
        profile.confidence  = confidence

        profile.techniques = self._technique_analyzer.analyze(profile)
        profile.intent     = self._intent_analyzer.analyze(profile)

        fp_data = (
            "|".join(sorted(profile.source_ips)) +
            "|" + actor.value +
            "|" + "|".join(sorted(str(t) for t in profile.techniques))
        )
        profile.fingerprint = hashlib.sha256(fp_data.encode()).hexdigest()[:16]

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

        minefield.register_forensic_callback(forensic.on_mine_contact)
        detector.register_forensic_callback(forensic.on_detection_event)
        bubble.register_forensic_callback(forensic.on_bubble_interaction)
        lockdown.register_forensic_callback(forensic.on_lockdown_snapshot)

        incident_id = forensic.open_incident(["1.2.3.4"])
        profile = forensic.analyze(incident_id)
        forensic.close_incident(incident_id)
    """

    def __init__(self, persistence=None):
        self._engine    = ForensicEngine()
        self._incidents: dict = {}
        self._closed:    dict = {}

        self._callbacks_learning: list = []
        self._persistence = persistence

        if persistence:
            self._incidents_dir = persistence.incidents_dir
        else:
            self._incidents_dir = Path("state/incidents")
            self._incidents_dir.mkdir(parents=True, exist_ok=True)

        logger.info("[AEGIS.Forensic] Capa 7 inicializada — motor forense listo")

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def register_learning_callback(self, cb: Callable) -> None:
        """
        Registers a Layer 8 (learning) callback to receive closed incident profiles.

        The callback is invoked asynchronously when an incident is closed via
        ``close_incident`` or ``close_incident_async``. Multiple callbacks
        can be registered and all will be called in registration order.

        Args:
            cb: A callable (sync or async) that accepts a single
                ``IntruderProfile`` argument. Async callbacks are awaited;
                sync callbacks are called directly.
        """
        self._callbacks_learning.append(cb)

    # ── Gestión de incidentes ─────────────────────────────────────────────────

    def open_incident(self, source_ips: list) -> str:
        """
        Opens a new forensic incident for the given source IP addresses.

        Creates a fresh ``IntruderProfile``, assigns it a unique incident ID,
        and registers it as an active incident. The profile remains mutable
        until ``close_incident`` is called.

        Args:
            source_ips: A list of IP address strings associated with the
                intruder triggering this incident.

        Returns:
            str: A unique incident ID (6-byte hex, uppercased) that identifies
                this incident in subsequent calls.
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
        Closes an active incident, runs final analysis, and notifies Layer 8.

        Removes the incident from the active registry, runs a full forensic
        analysis pass, persists the profile to disk, and fires all registered
        learning callbacks. The profile becomes immutable after closing.

        Args:
            incident_id: The unique ID of the incident to close, as returned
                by ``open_incident``.

        Returns:
            IntruderProfile: The fully analyzed and closed profile, or None
                if no active incident with the given ID exists.
        """
        profile = self._incidents.pop(incident_id, None)
        if not profile:
            return None

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

        if self._callbacks_learning:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self._notify_learning(profile))
                else:
                    loop.run_until_complete(self._notify_learning(profile))
            except RuntimeError:
                for cb in self._callbacks_learning:
                    try:
                        if not asyncio.iscoroutinefunction(cb):
                            cb(profile)
                    except Exception as e:
                        logger.warning(f"[FORENSIC] Error en callback: {e}")

        return profile

    async def close_incident_async(self, incident_id: str) -> Optional[IntruderProfile]:
        """
        Async variant of ``close_incident`` for use inside running event loops.

        Runs the final forensic analysis, persists the profile, and awaits
        all registered learning callbacks. Prefer this method when calling
        from within an async context.

        Args:
            incident_id: The unique ID of the incident to close.

        Returns:
            IntruderProfile: The analyzed and closed profile, or None if
                no active incident with the given ID exists.
        """
        profile = self._incidents.pop(incident_id, None)
        if not profile:
            return None

        profile = self._engine.analyze(profile)
        self._closed[incident_id] = profile
        self._persist_incident(incident_id, profile)

        await self._notify_learning(profile)
        return profile

    def _persist_incident(self, incident_id: str, profile: 'IntruderProfile') -> None:
        """Escribe el perfil del incidente a disco con fsync."""
        if self._persistence:
            self._persistence.save_incident(incident_id, profile.to_dict())
            return
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

    async def _notify_learning(self, profile: IntruderProfile) -> None:
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

    async def on_mine_contact(self, contact) -> None:
        """
        Receives a honeypot contact event from Layer 2 (minefield).

        Finds or creates an active incident for the contact's source IP,
        then delegates ingestion to the forensic engine.

        Args:
            contact: A mine contact object with at least a ``source_ip``
                attribute identifying the originating IP address.
        """
        ip      = getattr(contact, "source_ip", "unknown")
        profile = self._find_or_create_incident([ip])
        self._engine.ingest_mine_contact(profile, contact)

    async def on_detection_event(self, event) -> None:
        """
        Receives a detection event from Layer 3 (detector).

        Finds or creates an active incident for the event's source IPs,
        then delegates ingestion to the forensic engine.

        Args:
            event: A detection event object with an optional ``source_ips``
                attribute (list of IP address strings).
        """
        ips     = getattr(event, "source_ips", ["unknown"])
        profile = self._find_or_create_incident(ips)
        self._engine.ingest_detection_event(profile, event)

    async def on_bubble_interaction(self, interaction) -> None:
        """
        Receives a bubble interaction event from Layer 6.

        Assigns the interaction to the most recently opened active incident.
        Does nothing if no active incidents exist.

        Args:
            interaction: A bubble interaction object describing activity
                observed inside the deception environment.
        """
        if not self._incidents:
            return
        profile = list(self._incidents.values())[-1]
        self._engine.ingest_bubble_interaction(profile, interaction)

    async def on_lockdown_snapshot(self, snapshot: dict) -> None:
        """
        Receives a lockdown snapshot from Layer 4.

        Assigns the snapshot to the most recently opened active incident.
        Does nothing if no active incidents exist.

        Args:
            snapshot: A dictionary containing the system state captured
                by Layer 4 at the moment of lockdown.
        """
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
        """
        Runs a forensic analysis pass on an active incident without closing it.

        Useful for inspecting the current state of an ongoing incident.
        The incident remains open and continues to accept new evidence.

        Args:
            incident_id: The unique ID of the active incident to analyze.

        Returns:
            IntruderProfile: The updated profile with current analysis results,
                or None if no active incident with the given ID exists.
        """
        profile = self._incidents.get(incident_id)
        if not profile:
            return None
        return self._engine.analyze(profile)

    def score_threat(self, incident_id: str) -> Optional[dict]:
        """
        Calculates the predictive threat score for an incident at any point in time.

        Can be called on both active and closed incidents without affecting
        their state. Useful for real-time threat monitoring during an ongoing
        incident.

        Args:
            incident_id: The unique ID of the incident to score.

        Returns:
            dict: A threat assessment dictionary with score, level,
                will_escalate, recommendation, and breakdown fields,
                or None if the incident does not exist.
        """
        profile = self._incidents.get(incident_id) or \
                  self._closed.get(incident_id)
        if not profile:
            return None
        return self._engine._threat_scorer.score(profile)

    # ── Consultas ─────────────────────────────────────────────────────────────

    def get_profile(self, incident_id: str) -> Optional[dict]:
        """
        Returns the serialized profile for a given incident ID.

        Searches both active and closed incidents. Returns None if the
        incident does not exist in either registry.

        Args:
            incident_id: The unique ID of the incident to retrieve.

        Returns:
            dict: The JSON-serializable profile dictionary, or None if
                the incident does not exist.
        """
        p = self._incidents.get(incident_id) or self._closed.get(incident_id)
        return p.to_dict() if p else None

    def get_all_profiles(self) -> list:
        """
        Returns serialized profiles for all active and closed incidents.

        Returns:
            list: A list of profile dictionaries, active incidents first
                followed by closed incidents.
        """
        all_p = list(self._incidents.values()) + list(self._closed.values())
        return [p.to_dict() for p in all_p]

    def active_incidents(self) -> int:
        """
        Returns the number of currently active (open) incidents.

        Returns:
            int: Count of incidents that have been opened but not yet closed.
        """
        return len(self._incidents)

    def closed_incidents(self) -> int:
        """
        Returns the number of closed incidents held in memory.

        Returns:
            int: Count of incidents that have been fully analyzed and closed.
        """
        return len(self._closed)

    def status(self) -> dict:
        """
        Returns a summary of the current forensic layer state.

        Returns:
            dict: A status dictionary containing:
                - active_incidents (int): Number of open incidents.
                - closed_incidents (int): Number of closed incidents in memory.
                - total_incidents (int): Sum of active and closed incidents.
                - incidents_on_disk (int): Number of incident JSONL files
                  found in the incidents directory.
        """
        return {
            "active_incidents":  self.active_incidents(),
            "closed_incidents":  self.closed_incidents(),
            "total_incidents":   self.active_incidents() + self.closed_incidents(),
            "incidents_on_disk": len(list(self._incidents_dir.glob("*.jsonl"))),
        }
