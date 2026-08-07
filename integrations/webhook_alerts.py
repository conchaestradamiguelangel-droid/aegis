"""
AEGIS — Integración de webhooks genéricos (Discord/Slack/generic).

Envía un POST JSON al cerrar cada incidente forense (Capa 7), en modo
fire-and-forget, sin bloquear la ruta de detección (Capa 3). Sigue el
mismo patrón que integrations/telegram_alerts.py: ejecuta el envío HTTP
en un executor y nunca propaga excepciones hacia el llamador.

Uso:
    WEBHOOK_URL=https://discord.com/api/webhooks/... (o Slack, o genérico)

    alerter = WebhookAlerter(WebhookConfig(url=WEBHOOK_URL))
    forensic.register_learning_callback(alerter.on_incident_closed)
"""

import asyncio
import json
import logging
import time
import urllib.request
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class WebhookConfig:
    url: Optional[str] = None
    enabled: bool = True
    timeout_s: float = 5.0
    max_retries: int = 2
    retry_backoff_s: float = 1.0


class WebhookAlerter:
    """Capa 7 (forensic) → webhook externo, apagada por defecto (WEBHOOK_URL vacío)."""

    def __init__(self, config: WebhookConfig):
        self._cfg = config

    def _post(self, payload: dict) -> bool:
        """POST síncrono con reintento básico. Se ejecuta siempre en un executor."""
        if not self._cfg.enabled or not self._cfg.url:
            return False

        data = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        attempts = max(1, self._cfg.max_retries + 1)

        for attempt in range(attempts):
            try:
                req = urllib.request.Request(
                    self._cfg.url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self._cfg.timeout_s) as resp:
                    if 200 <= resp.status < 300:
                        return True
                    logger.warning(
                        f"[WEBHOOK] Respuesta no-2xx ({resp.status}) en intento {attempt + 1}/{attempts}"
                    )
            except Exception as e:
                logger.warning(f"[WEBHOOK] Error enviando (intento {attempt + 1}/{attempts}): {e}")

            if attempt < attempts - 1:
                time.sleep(self._cfg.retry_backoff_s)

        return False

    async def on_incident_closed(self, profile) -> None:
        """
        Callback registrable en AegisForensic.register_learning_callback().

        Se dispara cuando Capa 7 cierra un incidente. Construye el payload
        y despacha el POST en un executor — nunca bloquea el hilo de
        detección ni el resto de callbacks de aprendizaje.
        """
        if not self._cfg.enabled or not self._cfg.url:
            return

        try:
            assessment = getattr(profile, "threat_assessment", {}) or {}
            payload = {
                "source": "AEGIS",
                "incident_id": profile.incident_id,
                "incident_type": getattr(profile.intent, "value", str(profile.intent)),
                "actor_type": getattr(profile.actor_type, "value", str(profile.actor_type)),
                "severity": assessment.get("level", "DESCONOCIDO"),
                "score": assessment.get("score"),
                "timestamp": profile.last_seen.isoformat(),
                "source_ip": ", ".join(profile.source_ips) if profile.source_ips else "desconocida",
                "techniques": [getattr(t, "value", str(t)) for t in profile.techniques],
            }
        except Exception as e:
            logger.warning(f"[WEBHOOK] Error construyendo payload: {e}")
            return

        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, self._post, payload)
