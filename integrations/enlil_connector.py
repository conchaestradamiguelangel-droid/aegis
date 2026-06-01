"""
ENLIL Connector para AEGIS.
Envía detecciones a ENLIL para análisis del Consejo de Dioses.
Fire-and-forget — nunca bloquea el flujo defensivo de AEGIS.
"""

import asyncio
import json
import logging
import urllib.request
from typing import Optional

logger = logging.getLogger("aegis.enlil")

_SEVERITY_TO_TIER = {"low": "standard", "medium": "standard", "high": "full", "critical": "full"}


class EnlilConnector:
    """Envía alertas AEGIS al orquestador ENLIL para análisis multi-IA."""

    def __init__(self, enlil_url: str, api_key: str):
        self._url     = enlil_url.rstrip("/") + "/query"
        self._api_key = api_key

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
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except Exception as e:
            logger.error(f"[ENLIL] Error enviando alerta: {e}")
            return None

    async def _post(self, payload: dict) -> Optional[dict]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._post_sync(payload))

    async def on_threat_detected(self, detection) -> None:
        """Envía detección a ENLIL en background — no bloquea AEGIS."""
        dtype      = detection.detection_type.value if hasattr(detection.detection_type, "value") else str(detection.detection_type)
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
        log_indicators = "; ".join((detection.indicators or [])[:2])

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

        asyncio.create_task(self._send_and_log(payload, dtype))

    async def _send_and_log(self, payload: dict, alert_type: str) -> None:
        result = await self._post(payload)
        if result:
            decree_id = result.get("decree_id", "?")[:8]
            synthesis = result.get("synthesis", "")[:120]
            logger.info(
                f"[ENLIL] Decreto emitido — id={decree_id} tipo={alert_type}\n"
                f"        Síntesis: {synthesis}"
            )
        else:
            logger.warning(f"[ENLIL] Sin respuesta para alerta tipo={alert_type}")


def _confidence_to_severity(confidence: str) -> str:
    return {
        "CONFIRMED": "critical",
        "HIGH":      "high",
        "MEDIUM":    "medium",
        "LOW":       "low",
    }.get(confidence, "medium")
