"""
AEGIS — Integración MACE: Conector
====================================
Cierra el bucle entre los detectores de AEGIS y el proxy de MACE.

RESPONSABILIDADES:
    1. Recibe callbacks de C3 (detección confirmada)
    2. Añade la IP detectada a la blocklist del proxy
    3. Registra el evento en el log de integración
    4. Opcional: notifica a MACE por webhook si expone uno

DISEÑO:
    El conector es el único punto que conoce tanto a AEGIS como al proxy.
    MaceProxy no conoce a AEGIS. AEGIS no conoce a MaceProxy.
    El conector actúa como adaptador entre ambos.
"""
from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from layers.detector import DetectionEvent
    from layers.minefield import MineContact

from integrations.mace_proxy import MaceProxy, Blocklist
from core.wal import WALManager

logger = logging.getLogger("aegis.mace.connector")


class MaceConnector:
    """
    Conector AEGIS → MaceProxy.

    Uso:
        proxy     = MaceProxy(...)
        connector = MaceConnector(proxy)

        # Registrar en C3:
        aegis.detector.register_jump_callback(connector.on_detection)
        aegis.minefield.register_detection_callback(connector.on_mine_contact)

        # El conector bloquea automáticamente las IPs detectadas.
    """

    # TTL por defecto para IPs bloqueadas tras detección (segundos)
    DEFAULT_BLOCK_TTL_S = 3600   # 1 hora

    # TTL para bloqueo inmediato tras contacto con señuelo
    MINE_BLOCK_TTL_S = 7200      # 2 horas — señuelo = más peligroso

    def __init__(
        self,
        proxy:         MaceProxy,
        block_ttl_s:   Optional[int] = None,
        webhook_url:   Optional[str] = None,
        wal:           Optional[WALManager] = None,
    ) -> None:
        self._proxy        = proxy
        self._block_ttl    = block_ttl_s or self.DEFAULT_BLOCK_TTL_S
        if webhook_url is not None:
            if webhook_url.startswith("http://"):
                logger.warning(
                    f"[CONNECTOR] ⚠ webhook_url usa HTTP en lugar de HTTPS — "
                    f"las notificaciones viajarán en texto plano. "
                    f"Usa https:// para entornos productivos."
                )
            elif not webhook_url.startswith("https://"):
                raise ValueError(
                    f"webhook_url debe empezar con https:// (o http:// para dev). "
                    f"Recibido: {webhook_url[:30]}..."
                )
        self._webhook_url = webhook_url
        self._event_log:   list = []
        self._blocks_total = 0
        self._wal = wal

        logger.info(
            f"[CONNECTOR] MaceConnector inicializado — "
            f"TTL={self._block_ttl}s "
            f"webhook={'sí' if webhook_url else 'no'}"
        )

    # ── Callbacks para registrar en AEGIS ────────────────────────────────────

    async def on_detection(self, detection_event: DetectionEvent) -> None:
        """
        Callback para C3 (detector).
        Registrar con: aegis.detector.register_jump_callback(connector.on_detection)

        Bloquea todas las IPs de la detección en el proxy.
        """
        source_ips = getattr(detection_event, "source_ips", [])
        det_type   = getattr(
            detection_event, "detection_type", None
        )
        det_type_v = det_type.value if det_type is not None and hasattr(det_type, "value") else str(det_type)

        for ip in source_ips:
            self._block_ip(ip, self._block_ttl, reason=f"C3:{det_type_v}")

        self._log_event("DETECTION", source_ips, det_type_v)

        if self._webhook_url and source_ips:
            asyncio.create_task(
                self._notify_webhook("detection", source_ips, det_type_v)
            )

    async def on_mine_contact(self, contact: MineContact) -> None:
        """
        Callback para C2 (minefield).
        Registrar con: aegis.minefield.register_detection_callback(connector.on_mine_contact)

        Un toque a un señuelo es evidencia directa — bloqueo inmediato con TTL mayor.
        """
        ip        = getattr(contact, "source_ip",  "0.0.0.0")
        mine_name = getattr(contact, "mine_name",  "unknown")
        mine_type = getattr(contact, "mine_type",  "UNKNOWN")
        mine_tv   = mine_type.value if hasattr(mine_type, "value") else str(mine_type)

        self._block_ip(ip, self.MINE_BLOCK_TTL_S, reason=f"C2:{mine_tv}:{mine_name}")
        self._log_event("MINE_CONTACT", [ip], f"{mine_tv}:{mine_name}")

        if self._webhook_url:
            asyncio.create_task(
                self._notify_webhook("mine_contact", [ip], mine_name)
            )

    async def on_lockdown(self, snapshot: dict) -> None:
        """
        Callback para C4 (lockdown).
        Registrar con: aegis.lockdown.register_forensic_callback(connector.on_lockdown)

        Bloquea todas las sesiones activas registradas en el lockdown.
        """
        sessions = getattr(snapshot, "sessions_closed", {})
        ips      = list(sessions.keys()) if isinstance(sessions, dict) else []

        for ip in ips:
            self._block_ip(ip, self._block_ttl * 2, reason="C4:LOCKDOWN")

        self._log_event("LOCKDOWN", ips, "lockdown_executed")

    # ── Bloqueo manual ────────────────────────────────────────────────────────

    def block_ip(self, ip: str, ttl_s: Optional[int] = None, reason: str = "manual") -> None:
        """Bloquea una IP manualmente desde fuera del flujo de AEGIS."""
        self._block_ip(ip, ttl_s or self._block_ttl, reason=reason)

    def unblock_ip(self, ip: str) -> None:
        """Desbloquea una IP manualmente."""
        if self._wal:
            self._wal.write("unblock_ip", {"ip": ip})
        self._proxy.blocklist.unblock(ip)
        logger.info(f"[CONNECTOR] IP desbloqueada manualmente: {ip}")

    # ── Estado ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "blocks_total":    self._blocks_total,
            "active_blocks":   self._proxy.blocklist.active_count(),
            "blocked_ips":     self._proxy.blocklist.to_list(),
            "events_logged":   len(self._event_log),
            "webhook_url":     self._webhook_url,
            "proxy_stats":     self._proxy.stats.to_dict(),
        }

    def get_event_log(self) -> list:
        return list(self._event_log)

    # ── Internos ──────────────────────────────────────────────────────────────

    def _block_ip(self, ip: str, ttl_s: int, reason: str) -> None:
        """Bloquea una IP en el proxy y registra el bloqueo."""
        if self._wal:
            self._wal.write("block_ip", {"ip": ip, "ttl_s": ttl_s})
        self._proxy.blocklist.block(ip, ttl_s=ttl_s)
        self._blocks_total += 1
        logger.warning(
            f"[CONNECTOR] Bloqueando {ip} para MACE — "
            f"razón={reason} TTL={ttl_s}s"
        )

    def _log_event(self, event_type: str, ips: list, detail: str) -> None:
        """Añade entrada al log de integración."""
        self._event_log.append({
            "event_id":   secrets.token_hex(4).upper(),
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "source_ips": ips,
            "detail":     detail,
        })

    async def _notify_webhook(self, event_type: str, ips: list, detail: str) -> None:
        """
        Notifica a MACE vía webhook si está configurado.
        Fire-and-forget — fallo silencioso si MACE no responde.
        """
        url = self._webhook_url
        if not url:
            return
        try:
            import aiohttp
            payload = {
                "source": "AEGIS",
                "event":  event_type,
                "ips":    ips,
                "detail": detail,
                "ts":     datetime.now(timezone.utc).isoformat(),
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json    = payload,
                    timeout = aiohttp.ClientTimeout(total=5),
                ) as resp:
                    logger.info(
                        f"[CONNECTOR] Webhook enviado — "
                        f"status={resp.status} event={event_type}"
                    )
        except Exception as e:
            logger.debug(f"[CONNECTOR] Webhook falló (ignorado): {e}")
