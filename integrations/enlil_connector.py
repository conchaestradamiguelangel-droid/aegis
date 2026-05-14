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


class EnlilConnector:
    """Envía alertas AEGIS al orquestador ENLIL para análisis multi-IA."""

    def __init__(self, enlil_url: str, token: str):
        self._url   = enlil_url.rstrip("/") + "/aegis/analyze"
        self._token = token

    def _post_sync(self, payload: dict) -> Optional[dict]:
        body = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(
            self._url,
            data    = body,
            headers = {
                "Content-Type":  "application/json",
                "X-Aegis-Token": self._token,
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
        dtype   = detection.detection_type.value if hasattr(detection.detection_type, "value") else str(detection.detection_type)
        source_ip = list(detection.source_ips)[0] if detection.source_ips else None
        score   = getattr(detection, "threat_score", None)

        payload = {
            "type":      dtype,
            "severity":  _score_to_severity(score),
            "source_ip": source_ip,
            "target":    "AEGIS-VPS-001",
            "details": {
                "detection_id": detection.detection_id,
                "all_ips":      list(detection.source_ips) if detection.source_ips else [],
                "threat_score": str(score) if score is not None else "N/A",
            },
            "log": f"AEGIS detection: type={dtype} ips={list(detection.source_ips)}",
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


def _score_to_severity(score) -> str:
    if score is None:
        return "medium"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    if s >= 0.85:
        return "critical"
    if s >= 0.65:
        return "high"
    if s >= 0.40:
        return "medium"
    return "low"
