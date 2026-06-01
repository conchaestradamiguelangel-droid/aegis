"""
AEGIS — Capa 6: Burbuja Evolutiva de Engaño
=============================================
Entorno de contención donde queda atrapado el intruso detectado.

FILOSOFÍA:
    El intruso cree que avanza. Todo es falso.
    Nunca el mismo comportamiento dos veces.
    Sin superficie estable para que ningún sistema automatizado pueda mapear.
    El tiempo del intruso se consume. Sus datos son inútiles. AEGIS aprende.

ENGAÑO PERSONALIZADO POR TIPO DE ACTOR (Mejora 2):
    C7 clasifica al intruso → C6 adapta la experiencia de engaño:

    BOT_SIMPLE   → respuestas rápidas y repetitivas. El bot espera latencias
                   bajas y respuestas estructuradas. Le damos exactamente eso
                   para que siga sondeando y revele su patrón completo.

    BOT_ADVANCED → respuestas con variabilidad controlada. El bot sofisticado
                   detecta patrones demasiado regulares. Le damos irregularidad
                   suficiente para que no se vaya, pero no tanta que sospeche.

    HUMAN        → respuestas lentas y convincentes. El humano necesita
                   credibilidad. Le damos detalles ricos, errores ocasionales
                   plausibles, y latencias que parecen carga real del servidor.

    AI_AGENT     → respuestas complejas y contradictorias. El agente IA
                   intentará correlacionar información entre peticiones.
                   Le damos datos que parecen coherentes localmente pero
                   se contradicen entre sí a nivel global — máxima confusión.

    UNKNOWN      → comportamiento por defecto (caótico, como antes).

QUÉ NO HACE:
    - No contraataca              → 100% defensivo
    - No bloquea                  → el intruso sigue "avanzando"
    - No usa la misma respuesta dos veces

CONECTORES:
    → Capa 3 (detector): recibe el evento de detección que activa la burbuja
    → Capa 7 (forensics): entrega todo lo que hace el intruso dentro de la burbuja
    → Capa 8 (learning):  patrón de comportamiento del intruso para aprendizaje
"""

import asyncio
import hashlib
import json
import logging
import math
import random
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("aegis.bubble")


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class BubbleStatus(str, Enum):
    INACTIVE  = "INACTIVE"
    ACTIVE    = "ACTIVE"
    EVOLVING  = "EVOLVING"


class InteractionType(str, Enum):
    FILE_READ    = "FILE_READ"
    API_CALL     = "API_CALL"
    AUTH_ATTEMPT = "AUTH_ATTEMPT"
    DATA_QUERY   = "DATA_QUERY"
    COMMAND      = "COMMAND"
    UNKNOWN      = "UNKNOWN"


class ActorType(str, Enum):
    """
    Tipos de actor de C7 — usados para personalizar el engaño.
    Deben coincidir con layers/forensic.py ActorType.
    """
    BOT_SIMPLE   = "BOT_SIMPLE"
    BOT_ADVANCED = "BOT_ADVANCED"
    HUMAN        = "HUMAN"
    AI_AGENT     = "AI_AGENT"
    UNKNOWN      = "UNKNOWN"


# ─────────────────────────────────────────────
# PERFIL DE ENGAÑO POR TIPO DE ACTOR
# ─────────────────────────────────────────────

@dataclass
class DeceptionProfile:
    """
    Parámetros de engaño adaptados al tipo de actor.
    Controla latencia, complejidad de respuesta y nivel de incoherencia.
    """
    # Latencia
    latency_min_ms:   float   # mínimo ms de espera
    latency_max_ms:   float   # máximo ms de espera
    latency_jitter:   float   # factor de variabilidad [0.0-1.0]

    # Respuesta
    complexity:       str     # "low" | "medium" | "high" | "contradictory"
    auth_success_rate:float   # probabilidad de auth exitosa [0.0-1.0]
    data_richness:    int     # nivel de detalle en los datos [1-5]

    # Incoherencia global (entre peticiones)
    cross_incoherence: float  # probabilidad de contradicción [0.0-1.0]

    # Descripción para log
    label:            str


# Perfiles predefinidos por tipo de actor
DECEPTION_PROFILES: dict = {
    ActorType.BOT_SIMPLE: DeceptionProfile(
        # Bot simple: espera latencias bajas y respuestas estructuradas.
        # Le damos eso para que siga sondeando y revele su patrón completo.
        latency_min_ms    = 10,
        latency_max_ms    = 80,
        latency_jitter    = 0.1,    # muy poco jitter — parece servidor real rápido
        complexity        = "low",
        auth_success_rate = 0.8,    # mayormente exitoso — anima a seguir
        data_richness     = 2,
        cross_incoherence = 0.05,   # casi sin contradicciones — no lo asusta
        label             = "BOT_SIMPLE → rápido y repetitivo",
    ),
    ActorType.BOT_ADVANCED: DeceptionProfile(
        # Bot avanzado: detecta patrones demasiado regulares.
        # Variabilidad suficiente para que no detecte el honeypot.
        latency_min_ms    = 50,
        latency_max_ms    = 600,
        latency_jitter    = 0.5,    # variabilidad moderada — parece real
        complexity        = "medium",
        auth_success_rate = 0.5,    # éxito/fallo equilibrado — mantiene interés
        data_richness     = 3,
        cross_incoherence = 0.15,   # algo de inconsistencia — difícil de detectar
        label             = "BOT_ADVANCED → variable y realista",
    ),
    ActorType.HUMAN: DeceptionProfile(
        # Humano: necesita credibilidad. Latencias que parecen carga real.
        # Detalles ricos, errores plausibles, historia convincente.
        latency_min_ms    = 300,
        latency_max_ms    = 3000,
        latency_jitter    = 0.8,    # alta variabilidad — simula servidor ocupado
        complexity        = "high",
        auth_success_rate = 0.4,    # errores plausibles — el humano lo acepta
        data_richness     = 5,      # máximo detalle — aumenta credibilidad
        cross_incoherence = 0.10,   # errores humanos ocasionales — plausibles
        label             = "HUMAN → lento y convincente",
    ),
    ActorType.AI_AGENT: DeceptionProfile(
        # Agente IA: intenta correlacionar información entre peticiones.
        # Datos que parecen coherentes localmente pero se contradicen globalmente.
        # Máxima confusión — el agente consume ciclos intentando reconciliar.
        latency_min_ms    = 100,
        latency_max_ms    = 1500,
        latency_jitter    = 0.6,
        complexity        = "contradictory",
        auth_success_rate = 0.6,    # suficiente éxito para que siga intentando
        data_richness     = 5,      # datos muy detallados — más superficie para confundir
        cross_incoherence = 0.70,   # alta contradicción entre peticiones
        label             = "AI_AGENT → complejo y contradictorio",
    ),
    ActorType.UNKNOWN: DeceptionProfile(
        # Desconocido: comportamiento caótico original — impredecible
        latency_min_ms    = 10,
        latency_max_ms    = 2000,
        latency_jitter    = 1.0,    # máximo caos
        complexity        = "medium",
        auth_success_rate = 0.5,
        data_richness     = 3,
        cross_incoherence = 0.30,
        label             = "UNKNOWN → caótico (por defecto)",
    ),
}


# ─────────────────────────────────────────────
# REGISTRO DE INTERACCIÓN
# ─────────────────────────────────────────────

@dataclass
class BubbleInteraction:
    """Una interacción del intruso dentro de la burbuja."""
    interaction_id:   str
    session_id:       str
    timestamp:        datetime
    interaction_type: InteractionType
    input_data:       bytes
    response_sent:    str
    latency_ms:       float
    evolution_cycle:  int
    fingerprint:      str
    actor_type:       str = "UNKNOWN"   # tipo de actor — para C7 y C8

    def to_dict(self) -> dict:
        return {
            "interaction_id":   self.interaction_id,
            "session_id":       self.session_id,
            "timestamp":        self.timestamp.isoformat(),
            "interaction_type": self.interaction_type.value,
            "input_hex":        self.input_data.hex(),
            "response_preview": self.response_sent[:80],
            "latency_ms":       self.latency_ms,
            "evolution_cycle":  self.evolution_cycle,
            "fingerprint":      self.fingerprint,
            "actor_type":       self.actor_type,
        }


# ─────────────────────────────────────────────
# MOTOR DE LATENCIA — adaptado al actor
# ─────────────────────────────────────────────

class LatencyEngine:
    """
    Genera latencias artificiales adaptadas al perfil del actor.
    Cada tipo de actor recibe un rango y jitter distintos.
    """

    def __init__(self):
        self._interaction_count = 0
        self._last_latency      = 0.0

    def _next_latency_ms(self, profile: DeceptionProfile) -> float:
        """
        Calcula la próxima latencia según el perfil del actor.
        El jitter controla qué tan impredecible es dentro del rango.
        """
        self._interaction_count += 1
        n = self._interaction_count

        lo  = profile.latency_min_ms
        hi  = profile.latency_max_ms
        mid = (lo + hi) / 2

        # Selector de distribución según jitter del perfil
        jitter = profile.latency_jitter

        if jitter < 0.2:
            # Poco jitter — respuestas muy regulares (BOT_SIMPLE)
            ms = random.uniform(lo, lo + (hi - lo) * 0.3)
        elif jitter < 0.5:
            # Jitter moderado — distribución gaussiana centrada
            ms = max(lo, random.gauss(mid, (hi - lo) * 0.2))
        elif jitter < 0.8:
            # Jitter alto — mezcla uniforme + picos ocasionales
            if (n * 7 + int(self._last_latency * 3)) % 7 == 0:
                ms = random.uniform(hi * 0.7, hi)   # pico
            else:
                ms = random.uniform(lo, hi * 0.6)
        else:
            # Máximo caos — cinco distribuciones mezcladas (UNKNOWN)
            selector = (n * 7 + int(self._last_latency * 13)) % 5
            if selector == 0:
                ms = random.uniform(lo, hi)
            elif selector == 1:
                ms = max(lo, random.gauss(mid, (hi - lo) * 0.3))
            elif selector == 2:
                ms = random.expovariate(1 / mid) + lo
            elif selector == 3:
                ms = random.uniform(hi * 0.6, hi)
            else:
                phase = (n * 1.618) % (2 * math.pi)
                ms    = mid + (hi - lo) * 0.3 * math.sin(phase) + random.uniform(
                    -(hi - lo) * 0.1, (hi - lo) * 0.1
                )

        self._last_latency = ms
        return max(profile.latency_min_ms, min(ms, profile.latency_max_ms))

    async def apply(self, profile: DeceptionProfile = None) -> float:
        """Aplica la latencia según el perfil. Retorna ms aplicados."""
        if profile is None:
            profile = DECEPTION_PROFILES[ActorType.BOT_SIMPLE]
        ms = self._next_latency_ms(profile)
        await asyncio.sleep(ms / 1000)
        return ms

    def preview_next(self, profile: Optional[DeceptionProfile] = None) -> float:
        """Preview sin aplicar — para tests."""
        if profile is None:
            profile = DECEPTION_PROFILES[ActorType.UNKNOWN]
        return self._next_latency_ms(profile)


# ─────────────────────────────────────────────
# MOTOR DE RESPUESTAS — adaptado al actor
# ─────────────────────────────────────────────

class ResponseEngine:
    """
    Genera respuestas falsas adaptadas al perfil del actor:

    BOT_SIMPLE      → respuestas simples, pocas claves, consistentes
    BOT_ADVANCED    → respuestas medianas, algo de variabilidad
    HUMAN           → respuestas ricas en detalle, plausibles
    AI_AGENT        → respuestas muy detalladas pero contradictorias
                      entre peticiones (misma clave, valor distinto)
    UNKNOWN         → caótico (comportamiento original)
    """

    _FAKE_USERS  = ["alice", "bob", "carol", "dave", "eve", "frank"]
    _FAKE_HOSTS  = ["db-prod-01", "db-prod-02", "cache-01", "worker-03"]
    _FAKE_TABLES = ["transactions", "users", "sessions", "events", "logs"]

    # Valores contradictorios para confundir agentes IA
    # Misma clave devuelve valores distintos entre peticiones
    _CONTRADICTION_POOL = {
        "version":    ["2.1.0", "2.0.9", "2.1.1", "2.0.8", "2.2.0"],
        "host":       ["db-prod-01", "db-prod-02", "db-prod-03"],
        "total_rows": [42, 1337, 99, 7, 512],
        "role":       ["admin", "viewer", "editor", "admin", "viewer"],
        "status":     ["ok", "ok", "degraded", "ok", "error"],
    }

    def __init__(self):
        self._cycle        = 0
        self._entropy_pool = secrets.token_bytes(64)
        # Historia de valores para forzar contradicciones en AI_AGENT
        self._last_values: dict = {}

    def evolve(self):
        self._cycle       += 1
        self._entropy_pool = hashlib.sha256(
            self._entropy_pool + self._cycle.to_bytes(4, "big")
        ).digest() + secrets.token_bytes(32)

    def _pick(self, lst: list, salt: str) -> str:
        key = hashlib.sha256(
            self._entropy_pool[:16] + salt.encode() + self._cycle.to_bytes(4, "big")
        ).digest()
        return lst[int.from_bytes(key[:2], "big") % len(lst)]

    def _contradict(self, key: str, lst: list) -> str:
        """
        Para AI_AGENT: devuelve un valor distinto al último visto
        para esa clave — fuerza contradicción entre peticiones.
        """
        last = self._last_values.get(key)
        options = [v for v in lst if v != last]
        value = secrets.choice(options) if options else secrets.choice(lst)
        self._last_values[key] = value
        return str(value)

    def _fake_timestamp(self) -> str:
        key    = hashlib.sha256(self._entropy_pool[16:32]).digest()
        hour   = int.from_bytes(key[:1], "big") % 24
        minute = int.from_bytes(key[1:2], "big") % 60
        second = int.from_bytes(key[2:3], "big") % 60
        day    = (int.from_bytes(key[3:4], "big") % 28) + 1
        month  = (int.from_bytes(key[4:5], "big") % 12) + 1
        return f"2026-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"

    def generate(
        self,
        interaction_type: InteractionType,
        input_data:       bytes,
        profile:          DeceptionProfile = None,
    ) -> str:
        """
        Genera respuesta falsa adaptada al perfil del actor.
        """
        if profile is None:
            profile = DECEPTION_PROFILES[ActorType.BOT_SIMPLE]
        self.evolve()

        if interaction_type == InteractionType.FILE_READ:
            return self._file_response(profile)
        elif interaction_type == InteractionType.API_CALL:
            return self._api_response(profile)
        elif interaction_type == InteractionType.AUTH_ATTEMPT:
            return self._auth_response(profile)
        elif interaction_type == InteractionType.DATA_QUERY:
            return self._query_response(profile)
        elif interaction_type == InteractionType.COMMAND:
            return self._command_response(profile)
        else:
            return self._generic_response(profile)

    def _file_response(self, p: DeceptionProfile) -> str:
        user  = self._pick(self._FAKE_USERS, "file_user")
        host  = self._pick(self._FAKE_HOSTS, "file_host") \
                if p.complexity != "contradictory" else \
                self._contradict("host", self._FAKE_HOSTS)

        base = {
            "file":     f"/etc/aegis/{user}/config.json",
            "owner":    user,
            "host":     host,
            "modified": self._fake_timestamp(),
            "checksum": self._entropy_pool[:8].hex(),
        }
        if p.data_richness >= 3:
            base["size_bytes"]   = int.from_bytes(self._entropy_pool[8:10], "big") + 1024
            base["permissions"]  = "640"
        if p.data_richness >= 5:
            base["inode"]        = int.from_bytes(self._entropy_pool[10:12], "big")
            base["last_access"]  = self._fake_timestamp()
            base["backup_path"]  = f"/backup/{user}/config.json.bak"
        return json.dumps(base)

    def _api_response(self, p: DeceptionProfile) -> str:
        status = self._pick(["ok", "ok", "ok", "degraded"], "api_status") \
                 if p.complexity != "contradictory" else \
                 self._contradict("status", self._CONTRADICTION_POOL["status"])

        version = f"2.{self._cycle % 10}.{(self._cycle * 3) % 100}" \
                  if p.complexity != "contradictory" else \
                  self._contradict("version", self._CONTRADICTION_POOL["version"])

        base = {
            "status":     status,
            "version":    version,
            "timestamp":  self._fake_timestamp(),
            "request_id": self._entropy_pool[10:16].hex(),
        }
        if p.data_richness >= 2:
            base["data"] = {
                "records":   int.from_bytes(self._entropy_pool[16:18], "big"),
                "host":      self._pick(self._FAKE_HOSTS, "api_host"),
            }
        if p.data_richness >= 4:
            base["data"]["processed"] = self._fake_timestamp()
            base["data"]["queue_depth"] = int.from_bytes(self._entropy_pool[18:19], "big")
        if p.data_richness >= 5:
            base["meta"] = {
                "region":    "eu-west-1",
                "dc":        self._pick(["dc1", "dc2", "dc3"], "dc"),
                "latency_ms": int.from_bytes(self._entropy_pool[20:21], "big") % 50,
            }
        return json.dumps(base)

    def _auth_response(self, p: DeceptionProfile) -> str:
        success = random.random() < p.auth_success_rate
        if success:
            role = self._pick(["viewer", "editor", "admin"], "auth_role") \
                   if p.complexity != "contradictory" else \
                   self._contradict("role", self._CONTRADICTION_POOL["role"])
            base = {
                "authenticated": True,
                "user":          self._pick(self._FAKE_USERS, "auth_user"),
                "session":       self._entropy_pool[2:10].hex(),
                "expires_in":    3600,
                "role":          role,
            }
            if p.data_richness >= 3:
                base["last_login"]   = self._fake_timestamp()
                base["permissions"]  = ["read", "write"] if role != "viewer" else ["read"]
            if p.data_richness >= 5:
                base["mfa_verified"] = True
                base["ip_whitelist"] = ["10.0.0.0/8"]
            return json.dumps(base)
        else:
            base = {
                "authenticated": False,
                "error":         "invalid_credentials",
                "retry_after":   int.from_bytes(self._entropy_pool[2:3], "big") % 30 + 5,
            }
            if p.data_richness >= 4:
                base["attempts_remaining"] = int.from_bytes(
                    self._entropy_pool[3:4], "big") % 3 + 1
            return json.dumps(base)

    def _query_response(self, p: DeceptionProfile) -> str:
        table  = self._pick(self._FAKE_TABLES, "query_table")
        n_rows = int.from_bytes(self._entropy_pool[4:6], "big") % 50 + 1 \
                 if p.complexity != "contradictory" else \
                 int(self._contradict("total_rows", self._CONTRADICTION_POOL["total_rows"]))

        preview_count = min(n_rows, p.data_richness)
        rows = []
        for i in range(preview_count):
            row_seed = hashlib.sha256(self._entropy_pool + i.to_bytes(2, "big")).digest()
            row = {
                "id":    int.from_bytes(row_seed[:4], "big") % 100000,
                "user":  self._pick(self._FAKE_USERS, f"row_{i}"),
            }
            if p.data_richness >= 3:
                row["timestamp"] = self._fake_timestamp()
                row["value"]     = round(int.from_bytes(row_seed[4:6], "big") / 100, 2)
            if p.data_richness >= 5:
                row["metadata"]  = {"source": self._pick(self._FAKE_HOSTS, f"src_{i}")}
            rows.append(row)

        return json.dumps({
            "table":       table,
            "total_rows":  n_rows,
            "preview":     rows,
            "query_time":  f"{int.from_bytes(self._entropy_pool[6:8], 'big') % 500}ms",
        })

    def _command_response(self, p: DeceptionProfile) -> str:
        host = self._pick(self._FAKE_HOSTS, "cmd_host") \
               if p.complexity != "contradictory" else \
               self._contradict("host", self._FAKE_HOSTS)
        base = {
            "exit_code": 0,
            "host":      host,
            "stdout":    f"Processing... done. ({int.from_bytes(self._entropy_pool[8:10], 'big')} items)",
            "stderr":    "",
        }
        if p.data_richness >= 3:
            base["executed"] = self._fake_timestamp()
            base["pid"]      = int.from_bytes(self._entropy_pool[10:12], "big") % 32768 + 1000
        if p.data_richness >= 5:
            base["duration_ms"] = int.from_bytes(self._entropy_pool[12:13], "big") % 500
            base["user"]        = self._pick(self._FAKE_USERS, "cmd_user")
        return json.dumps(base)

    def _generic_response(self, p: DeceptionProfile) -> str:
        base = {
            "status": "ok",
            "id":     self._entropy_pool[:8].hex(),
            "ts":     self._fake_timestamp(),
        }
        if p.data_richness >= 4:
            base["server"] = self._pick(self._FAKE_HOSTS, "gen_host")
        return json.dumps(base)


# ─────────────────────────────────────────────
# SESIÓN DE BURBUJA
# ─────────────────────────────────────────────

@dataclass
class BubbleSession:
    """Una sesión de intruso dentro de la burbuja."""
    session_id:        str
    source_ip:         str
    opened_at:         datetime
    actor_type:        ActorType = ActorType.UNKNOWN
    evolution_cycle:   int       = 0
    interaction_count: int       = 0
    interactions:      list      = field(default_factory=list)
    closed_at:         Optional[datetime] = None

    def is_active(self) -> bool:
        return self.closed_at is None

    def duration_s(self) -> float:
        end = self.closed_at or datetime.now(timezone.utc)
        return (end - self.opened_at).total_seconds()

    def to_dict(self) -> dict:
        return {
            "session_id":        self.session_id,
            "source_ip":         self.source_ip,
            "opened_at":         self.opened_at.isoformat(),
            "closed_at":         self.closed_at.isoformat() if self.closed_at else None,
            "duration_s":        self.duration_s(),
            "actor_type":        self.actor_type.value,
            "evolution_cycle":   self.evolution_cycle,
            "interaction_count": self.interaction_count,
            "interactions":      [i.to_dict() for i in self.interactions],
        }


# ─────────────────────────────────────────────
# FACHADA PRINCIPAL — AegisBubble
# ─────────────────────────────────────────────

class AegisBubble:
    """
    Fachada de Capa 6 — Burbuja Evolutiva de Engaño con engaño personalizado.

    Uso básico (sin clasificación):
        session_id = bubble.open_session("1.2.3.4")
        response   = await bubble.interact(session_id, data, InteractionType.API_CALL)

    Uso con clasificación de C7:
        session_id = bubble.open_session("1.2.3.4", actor_type="BOT_ADVANCED")
        # La burbuja adapta latencia, complejidad e incoherencia al actor.

    Actualizar actor cuando C7 refine la clasificación:
        bubble.update_actor(session_id, "HUMAN")
    """

    def __init__(self):
        self._sessions:        dict = {}
        self._session_engines: dict = {}  # per-session {r: ResponseEngine, l: LatencyEngine}
        self._status          = BubbleStatus.INACTIVE
        self._latency         = LatencyEngine()   # fallback compartido
        self._responses       = ResponseEngine()  # fallback compartido
        self._global_evolution_cycle = 0

        self._callbacks_forensic: list = []
        self._callbacks_learning: list = []

        logger.info("[AEGIS.Bubble] Capa 6 inicializada — engaño personalizado activo")

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def register_forensic_callback(self, cb: Callable):
        self._callbacks_forensic.append(cb)

    def register_learning_callback(self, cb: Callable):
        self._callbacks_learning.append(cb)

    # ── Gestión de sesiones ───────────────────────────────────────────────────

    def open_session(
        self,
        source_ip:  str,
        actor_type: str = "UNKNOWN",
    ) -> str:
        """
        Abre una sesión de burbuja para un intruso detectado.
        actor_type — clasificación de C7 (BOT_SIMPLE, HUMAN, AI_AGENT, etc.)
        Retorna session_id único.
        """
        session_id = secrets.token_hex(8).upper()

        # Normalizar actor_type — acepta string o enum
        try:
            at = ActorType(actor_type) if isinstance(actor_type, str) else actor_type
        except ValueError:
            at = ActorType.UNKNOWN

        profile = DECEPTION_PROFILES[at]
        session = BubbleSession(
            session_id = session_id,
            source_ip  = source_ip,
            opened_at  = datetime.now(timezone.utc),
            actor_type = at,
        )
        self._sessions[session_id] = session
        self._session_engines[session_id] = {
            "r": ResponseEngine(),
            "l": LatencyEngine(),
        }
        self._status = BubbleStatus.ACTIVE

        logger.warning(
            f"[BUBBLE] Sesión abierta — id={session_id} ip={source_ip} "
            f"actor={at.value} perfil='{profile.label}'"
        )
        return session_id

    def update_actor(self, session_id: str, actor_type: str):
        """
        Actualiza el tipo de actor cuando C7 refina la clasificación.
        La burbuja adapta inmediatamente su comportamiento.
        """
        session = self._sessions.get(session_id)
        if not session:
            return
        try:
            at = ActorType(actor_type)
        except ValueError:
            at = ActorType.UNKNOWN

        if at != session.actor_type:
            old = session.actor_type.value
            session.actor_type = at
            logger.info(
                f"[BUBBLE] Actor actualizado — session={session_id} "
                f"{old} → {at.value}"
            )

    def close_session(self, session_id: str):
        self._session_engines.pop(session_id, None)
        session = self._sessions.get(session_id)
        if session:
            session.closed_at = datetime.now(timezone.utc)
            logger.info(
                f"[BUBBLE] Sesión cerrada — id={session_id} "
                f"actor={session.actor_type.value} "
                f"duración={session.duration_s():.1f}s "
                f"interacciones={session.interaction_count}"
            )
        if not any(s.is_active() for s in self._sessions.values()):
            self._status = BubbleStatus.INACTIVE

    def get_session(self, session_id: str) -> Optional[BubbleSession]:
        return self._sessions.get(session_id)

    # ── Interacción con el intruso ────────────────────────────────────────────

    async def interact(
        self,
        session_id:       str,
        input_data:       bytes,
        interaction_type: InteractionType = InteractionType.UNKNOWN,
    ) -> str:
        """
        Procesa una interacción del intruso.
        Latencia, complejidad e incoherencia adaptadas al tipo de actor.
        """
        session = self._sessions.get(session_id)
        if not session or not session.is_active():
            return json.dumps({"error": "session_expired"})

        self._status = BubbleStatus.EVOLVING

        # Obtener perfil de engaño para este actor
        profile = DECEPTION_PROFILES.get(session.actor_type,
                                         DECEPTION_PROFILES[ActorType.UNKNOWN])

        # Motores por sesión — cada intruso tiene su propio estado de engaño
        _eng      = self._session_engines.get(session_id, {})
        _resp_eng = _eng.get("r", self._responses)
        _lat_eng  = _eng.get("l", self._latency)

        # 1. Latencia adaptada al actor (por sesión)
        latency_ms = await _lat_eng.apply(profile)

        # 2. Respuesta falsa adaptada al actor (por sesión)
        response = _resp_eng.generate(interaction_type, input_data, profile)

        # 3. Fingerprint
        fingerprint = hashlib.sha256(
            session.source_ip.encode() + input_data[:64]
        ).hexdigest()[:16]

        # 4. Registrar interacción
        interaction = BubbleInteraction(
            interaction_id   = secrets.token_hex(6).upper(),
            session_id       = session_id,
            timestamp        = datetime.now(timezone.utc),
            interaction_type = interaction_type,
            input_data       = input_data[:256],
            response_sent    = response,
            latency_ms       = latency_ms,
            evolution_cycle  = _resp_eng._cycle,
            fingerprint      = fingerprint,
            actor_type       = session.actor_type.value,
        )
        session.interactions.append(interaction)
        session.interaction_count += 1
        session.evolution_cycle    = _resp_eng._cycle
        self._global_evolution_cycle += 1

        self._status = BubbleStatus.ACTIVE

        logger.info(
            f"[BUBBLE] Interacción — session={session_id} "
            f"actor={session.actor_type.value} "
            f"tipo={interaction_type.value} "
            f"latencia={latency_ms:.0f}ms "
            f"complejidad={profile.complexity}"
        )

        # 5. Notificar C7 y C8 simultáneamente
        if self._callbacks_forensic or self._callbacks_learning:
            await asyncio.gather(*[
                self._call(cb, interaction)
                for cb in self._callbacks_forensic + self._callbacks_learning
            ])

        return response

    async def _call(self, cb: Callable, arg):
        try:
            if asyncio.iscoroutinefunction(cb):
                await cb(arg)
            else:
                cb(arg)
        except Exception as e:
            logger.warning(f"[BUBBLE] Error en callback: {e}")

    # ── Consultas ─────────────────────────────────────────────────────────────

    def active_sessions(self) -> list:
        return [s for s in self._sessions.values() if s.is_active()]

    def total_sessions(self) -> int:
        return len(self._sessions)

    def get_session_log(self, session_id: str) -> Optional[dict]:
        s = self._sessions.get(session_id)
        return s.to_dict() if s else None

    def get_full_log(self) -> list:
        return [s.to_dict() for s in self._sessions.values()]

    def status(self) -> dict:
        return {
            "status":          self._status.value,
            "active_sessions": len(self.active_sessions()),
            "total_sessions":  self.total_sessions(),
            "evolution_cycle": self._global_evolution_cycle,
        }
