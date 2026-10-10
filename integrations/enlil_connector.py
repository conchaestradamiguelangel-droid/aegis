"""
ENLIL Connector para AEGIS.
Envía detecciones a ENLIL para análisis del Consejo de Dioses.
Fire-and-forget — nunca bloquea el flujo defensivo de AEGIS.

Garantías (el gasto lo controla EXCLUSIVAMENTE el Cost Guard de ENLIL; aquí
solo hay límites de higiene para no saturar a AEGIS ni a ENLIL):
  - Interruptor ENLIL_BRIDGE_ENABLED (apagado por defecto).
  - Nunca propaga una excepción al camino de detección/lockdown.
  - Timeout acotado, SIN reintentos (un fallo se registra y se descarta).
  - Como mucho _MAX_INFLIGHT llamadas simultáneas; si está lleno se descarta.
  - Misma detección (tipo + IPs) no se reenvía durante _DEDUPE_WINDOW_S.
  - Tope de _MAX_PER_HOUR llamadas/hora, por debajo del rate limit de ENLIL.
  - Sin bucle posible: ENLIL no llama a AEGIS y la respuesta solo se registra.
  - Los logs nunca incluyen la API key.
"""

import asyncio
import json
import logging
import os
import time
import urllib.request
from collections import deque
from typing import Optional

logger = logging.getLogger("aegis.enlil")

_SEVERITY_TO_TIER = {"low": "standard", "medium": "standard", "high": "full", "critical": "full"}

# Tipos de detección que NO se envían al Consejo de ENLIL.
# AUTOMATED (velocidad de bot/script) es ruido de fondo rutinario de
# cualquier VPS público — AEGIS ya decide y ejecuta LOCKDOWN de forma
# autónoma sin esperar al Consejo. Enviarlo consumía el tier más caro
# (9 dioses + Marduk) para tráfico que no requiere deliberación multi-IA.
_SKIP_ENLIL_TYPES = {"AUTOMATED"}

_TIMEOUT_S        = 120    # un Consejo "full" puede tardar; el hilo queda acotado igualmente
_MAX_INFLIGHT     = 2      # llamadas simultáneas a ENLIL; el resto se descarta
_DEDUPE_WINDOW_S  = 300    # misma detección (tipo + IPs) no se reenvía en 5 min
_MAX_PER_HOUR     = 10     # < max_requests_per_hour (12) del cliente AEGIS en ENLIL


class EnlilConnector:
    """Envía alertas AEGIS al orquestador ENLIL para análisis multi-IA."""

    def __init__(self, enlil_url: str, api_key: str):
        self._url     = enlil_url.rstrip("/") + "/query"
        self._api_key = api_key
        # Interruptor manual del bridge — apagado por defecto (decisión 16/08/2026).
        # AEGIS ya defiende en solitario (lockdown, minefield, etc. no dependen de
        # ENLIL); el bridge solo añade un informe deliberado por el Consejo, y
        # dejarlo en automático disparó gasto real no controlado en OpenRouter
        # (~$28 entre el 6 y el 11 de agosto). Nadie consulta al Consejo salvo
        # que se active explícitamente. Para reactivarlo: ENLIL_BRIDGE_ENABLED=true
        # en el .env de AEGIS + reinicio del servicio.
        self._enabled = os.environ.get("ENLIL_BRIDGE_ENABLED", "false").strip().lower() == "true"
        self._inflight   = 0
        self._recent: dict = {}              # clave de detección -> instante del último envío
        self._sent_times: deque = deque()    # instantes de envíos de la última hora
        self._tasks: set = set()             # referencias fuertes a las tareas en vuelo
        if self._enabled:
            logger.info("[ENLIL] Bridge ACTIVADO — las detecciones se enviarán al Consejo")
        else:
            logger.info("[ENLIL] Bridge DESACTIVADO — ninguna detección se envía al Consejo (ENLIL_BRIDGE_ENABLED=false)")

    def _post_sync(self, payload: dict) -> Optional[dict]:
        body = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            self._url,
            data    = body,
            headers = {
                "Content-Type": "application/json",
                "X-Api-Key":    self._api_key,
            },
            method = "POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
                return json.loads(resp.read())
        except Exception as e:
            # str(e) de urllib no contiene cabeceras ni la API key.
            logger.error(f"[ENLIL] Error enviando alerta: {type(e).__name__}: {e}")
            return None

    async def _post(self, payload: dict) -> Optional[dict]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self._post_sync(payload))

    def _admit(self, key) -> Optional[str]:
        """Devuelve None si se puede enviar, o el motivo del descarte."""
        now = time.monotonic()
        if self._inflight >= _MAX_INFLIGHT:
            return "máximo de llamadas simultáneas"
        last = self._recent.get(key)
        if last is not None and now - last < _DEDUPE_WINDOW_S:
            return "detección duplicada reciente"
        while self._sent_times and now - self._sent_times[0] >= 3600:
            self._sent_times.popleft()
        if len(self._sent_times) >= _MAX_PER_HOUR:
            return "tope por hora"
        # Registro: poda de claves caducadas para que el dict no crezca sin límite.
        if len(self._recent) > 256:
            self._recent = {k: t for k, t in self._recent.items() if now - t < _DEDUPE_WINDOW_S}
        self._recent[key] = now
        self._sent_times.append(now)
        return None

    async def on_threat_detected(self, detection) -> None:
        """Envía detección a ENLIL en background — no bloquea AEGIS ni lanza excepciones."""
        if not self._enabled:
            return
        try:
            await self._dispatch(detection)
        except Exception as e:
            # Fail-safe: ningún fallo del bridge puede llegar al lockdown.
            logger.warning(f"[ENLIL] Bridge omitido por error interno: {type(e).__name__}: {e}")

    async def _dispatch(self, detection) -> None:
        dtype = detection.detection_type.value if hasattr(detection.detection_type, "value") else str(detection.detection_type)
        if dtype in _SKIP_ENLIL_TYPES:
            logger.debug(f"[ENLIL] Detección tipo={dtype} omitida — ruido rutinario, AEGIS ya actúa solo")
            return

        confidence = detection.confidence.value if hasattr(detection.confidence, "value") else str(detection.confidence)
        source_ip  = list(detection.source_ips)[0] if detection.source_ips else "desconocida"
        severity   = _confidence_to_severity(confidence)

        evidence = detection.evidence or {}
        evidence_slim = {}
        for key in ["paths_touched", "ports_touched", "requests_per_second",
                    "time_active_s", "mine_type", "severity", "active_ips", "window_s"]:
            if key in evidence:
                val = evidence[key]
                evidence_slim[key] = list(val)[:10] if isinstance(val, (list, set)) else val

        indicators = (detection.indicators or [])[:5]
        ind_str    = "; ".join(str(i) for i in indicators[:4]) if indicators else "sin indicadores"
        log_indicators = "; ".join(str(i) for i in (detection.indicators or [])[:2])

        query = (
            f"Alerta AEGIS — Tipo: {dtype} | Severidad: {severity} | Confianza: {confidence} | "
            f"IP origen: {source_ip} | Objetivo: AEGIS-VPS-001\n"
            f"Indicadores: {ind_str}\n"
            f"Detalles: detection_id={detection.detection_id} all_ips={list(detection.source_ips)} "
            f"action={detection.action_required} {evidence_slim}\n"
            f"Log: AEGIS detection: type={dtype} confidence={confidence} "
            f"ips={list(detection.source_ips)} | {log_indicators}"
        )
        context = (
            "Eres el Consejo de ENLIL analizando una alerta del sistema AEGIS "
            "(plataforma de ciberdefensa autónoma post-cuántica de 10 capas). "
            "Tu misión: analizar la amenaza, evaluar severidad real, "
            "proponer contramedidas concretas y decidir si escalar."
        )

        payload = {
            "query":       query,
            "context":     context,
            "budget_tier": _SEVERITY_TO_TIER.get(severity, "standard"),
        }

        key = (dtype, tuple(sorted(str(ip) for ip in (detection.source_ips or []))))
        reason = self._admit(key)
        if reason:
            logger.info(f"[ENLIL] Alerta tipo={dtype} no enviada al Consejo ({reason}) — AEGIS actúa solo")
            return

        self._inflight += 1
        try:
            task = asyncio.create_task(self._send_and_log(payload, dtype))
        except Exception:
            self._inflight -= 1
            raise
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _send_and_log(self, payload: dict, alert_type: str) -> None:
        try:
            result = await self._post(payload)
            if not isinstance(result, dict) or not result:
                logger.warning(f"[ENLIL] Sin respuesta válida para alerta tipo={alert_type}")
                return
            decree_id = str(result.get("decree_id") or "?")[:8]
            status    = str(result.get("status") or "?")[:20]
            synthesis = str(result.get("synthesis") or "")[:120]
            logger.info(
                f"[ENLIL] Decreto emitido — id={decree_id} tipo={alert_type} estado={status}\n"
                f"        Síntesis: {synthesis}"
            )
        except Exception as e:
            logger.warning(f"[ENLIL] Fallo procesando respuesta tipo={alert_type}: {type(e).__name__}: {e}")
        finally:
            self._inflight -= 1


def _confidence_to_severity(confidence: str) -> str:
    return {
        "CONFIRMED": "critical",
        "HIGH":      "high",
        "MEDIUM":    "medium",
        "LOW":       "low",
    }.get(confidence, "medium")
