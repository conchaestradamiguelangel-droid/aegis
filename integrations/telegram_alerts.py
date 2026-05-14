"""
Alertas Telegram para AEGIS.
Notificaciones en tiempo real de amenazas detectadas en producción.
"""

import asyncio
import logging
import urllib.request
import json
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AlertConfig:
    token:   str
    chat_id: str
    enabled: bool = True


class TelegramAlerter:
    """Envía alertas a Telegram cuando AEGIS detecta amenazas."""

    def __init__(self, config: AlertConfig):
        self._cfg     = config
        self._api_url = f"https://api.telegram.org/bot{config.token}/sendMessage"
        # Canales independientes de rate limiting para no bloquear mensajes relacionados
        self._last_sent_detection: float = 0.0
        self._last_sent_result:    float = 0.0
        self._last_sent_misc:      float = 0.0
        self._min_interval = 3.0

    def _send(self, text: str, channel: str = "misc") -> bool:
        if not self._cfg.enabled:
            return False

        now = time.time()
        attr = f"_last_sent_{channel}"
        last = getattr(self, attr, 0.0)
        if now - last < self._min_interval:
            return False
        setattr(self, attr, now)

        payload = json.dumps({
            "chat_id":    self._cfg.chat_id,
            "text":       text,
            "parse_mode": "HTML",
            "disable_notification": False,
        }).encode("utf-8")

        try:
            req = urllib.request.Request(
                self._api_url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception as e:
            logger.error(f"[TELEGRAM] Error enviando alerta: {e}")
            if getattr(self, attr, None) == now:
                setattr(self, attr, 0.0)
            return False

    async def on_threat_detected(self, detection, with_bubble: bool = False) -> None:
        """Alerta inmediata — se envía antes del lockdown."""
        ips   = ", ".join(detection.source_ips) if detection.source_ips else "desconocida"
        dtype = detection.detection_type.value if hasattr(detection.detection_type, "value") else str(detection.detection_type)
        score = getattr(detection, "threat_score", None)
        score_str = f"\n⚠️ Score: <code>{score:.2f}</code>" if score is not None else ""

        contramedidas = [
            "🔒 Cierre atómico de sesiones",
            "🔑 Rotación de credenciales",
            "🚪 Cierre de superficies de ataque",
            "🔬 Snapshot forense",
        ]
        if with_bubble:
            contramedidas.insert(0, "🫧 Burbuja de engaño activada")
            contramedidas.append("🔄 Salto de gemelo cuántico")

        contramedidas_str = "\n".join(f"  {c}" for c in contramedidas)

        text = (
            f"🚨 <b>AEGIS — AMENAZA DETECTADA</b>\n\n"
            f"🔴 Tipo: <code>{dtype}</code>\n"
            f"🌐 IP: <code>{ips}</code>"
            f"{score_str}\n"
            f"🆔 ID: <code>{detection.detection_id}</code>\n\n"
            f"⚔️ <b>Contramedidas activadas:</b>\n{contramedidas_str}"
        )
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._send(text, channel="detection")
        )

    async def on_mine_contact(self, event: dict) -> None:
        """Alerta cuando alguien toca un señuelo del campo de minas."""
        ip   = event.get("source_ip", "desconocida")
        mine = event.get("mine_id", "—")

        text = (
            f"⚠️ <b>AEGIS — SEÑUELO ACTIVADO</b>\n\n"
            f"🌐 IP: <code>{ip}</code>\n"
            f"🪤 Señuelo: <code>{mine}</code>\n"
            f"👁️ Comportamiento malicioso registrado"
        )
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._send(text, channel="misc")
        )

    async def on_lockdown(self, lockdown_id: str, result=None, source_ips: list = None) -> None:
        """Resultado completo del lockdown — amenaza neutralizada, fallo o límites superados."""
        ips_str = ""
        if source_ips:
            ips_str = f"🌐 IP bloqueada: <code>{', '.join(source_ips)}</code>\n"

        if result is not None:
            success   = getattr(result, "success", True)
            total_ms  = getattr(result, "total_ms", 0.0)
            twin_ms   = getattr(result, "twin_jump_ms", 0.0)
            sessions  = getattr(result, "sessions_invalidated", 0)
            creds     = getattr(result, "credentials_rotated", 0)
            surfaces  = getattr(result, "surfaces_closed", 0)
            within    = result.within_limits() if hasattr(result, "within_limits") else True

            estado_icon  = "✅" if success else "❌"
            estado_texto = "AMENAZA NEUTRALIZADA" if success else "LOCKDOWN CON ERRORES"
            timing_icon  = "⚡" if within else "🐢"

            twin_str     = f"🔄 Gemelo saltado: <code>{twin_ms:.0f}ms</code>\n" if twin_ms > 0 else ""
            sesiones_str = f"🔐 Sesiones invalidadas: <code>{sessions}</code>\n" if sessions > 0 else ""
            creds_str    = f"🔑 Credenciales rotadas: <code>{creds}</code>\n" if creds > 0 else ""
            surfaces_str = f"🚪 Superficies cerradas: <code>{surfaces}</code>\n" if surfaces > 0 else ""

            limite_aviso = ""
            if not within:
                limite_aviso = f"\n⚠️ <b>ADVERTENCIA:</b> Operaciones superaron el límite de 100ms\n"

            text = (
                f"{estado_icon} <b>AEGIS — {estado_texto}</b>\n\n"
                f"{ips_str}"
                f"{twin_str}"
                f"{sesiones_str}"
                f"{creds_str}"
                f"{surfaces_str}"
                f"{timing_icon} Tiempo total: <code>{total_ms:.0f}ms</code>\n"
                f"🆔 Lockdown ID: <code>{lockdown_id}</code>"
                f"{limite_aviso}"
            )
        else:
            text = (
                f"🔒 <b>AEGIS — LOCKDOWN EJECUTADO</b>\n\n"
                f"{ips_str}"
                f"⏱️ Cierre atómico completado\n"
                f"🔄 Gemelo saltado — reconocimiento del atacante invalidado\n"
                f"🆔 ID: <code>{lockdown_id}</code>"
            )

        await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._send(text, channel="result")
        )

    async def send_startup(self) -> None:
        """Notificación de arranque del sistema."""
        text = (
            f"✅ <b>AEGIS — SISTEMA OPERATIVO</b>\n\n"
            f"🛡️ 10 capas activas\n"
            f"🔐 Criptografía post-cuántica inicializada\n"
            f"👁️ Monitorización 24/7 activa"
        )
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._send(text, channel="misc")
        )

    async def send_test(self) -> bool:
        """Test de conectividad — verificar token y chat_id."""
        text = "🧪 <b>AEGIS — Test de alertas OK</b>\nSistema de notificaciones funcionando."
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self._send(text, channel="misc"))

    async def send_pir(self, report: dict) -> None:
        """Post-Incident Report -- resumen conciso tras neutralizar amenaza."""
        t   = report.get("threat", {})
        res = report.get("response", {})
        f   = report.get("forensic", {})
        tw  = report.get("twin", {})

        ips      = ", ".join(t.get("source_ips", [])) or "desconocida"
        verdict  = report.get("verdict", "DESCONOCIDO")
        icon     = "✅" if verdict == "NEUTRALIZADO" else "⚠️"
        techs    = ", ".join(f.get("techniques", [])) or "—"
        twin_str = f"🔄 Salto gemelo: <code>{tw.get('duration_ms', 0):.0f}ms</code>\n" if tw else ""

        text = (
            f"{icon} <b>AEGIS — PIR: {verdict}</b>\n\n"
            f"🆔 <code>{report.get('incident_id', '—')}</code>\n"
            f"🌐 IP: <code>{ips}</code>\n"
            f"🔴 Tipo: <code>{t.get('type', '—')}</code>\n\n"
            f"<b>Respuesta:</b>\n"
            f"⏱ Lockdown: <code>{res.get('total_ms', 0):.0f}ms</code>\n"
            f"{twin_str}"
            f"🔐 Sesiones: <code>{res.get('sessions_sealed', 0)}</code> &nbsp;"
            f"🔑 Creds: <code>{res.get('credentials_rotated', 0)}</code>\n\n"
            f"<b>Forense (C7):</b>\n"
            f"🎭 Actor: <code>{f.get('actor', '—')}</code>\n"
            f"🎯 Intencion: <code>{f.get('intent', '—')}</code>\n"
            f"⚡ Nivel: <code>{f.get('threat_level', '—')}</code> "
            f"({f.get('threat_score', 0):.2f})\n"
            f"🔧 Tecnicas: <code>{techs}</code>"
        )
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._send(text, channel="misc")
        )
