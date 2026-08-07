"""
AEGIS — Forwarder de incidentes a syslog-ng / rsyslog (RFC 5424).

Reenvía cada incidente cerrado por Capa 7 (forensic) a un colector syslog
externo vía UDP, usando exclusivamente logging.handlers.SysLogHandler de
la stdlib — sin dependencias nuevas. Apagado por defecto: solo se activa
si SYSLOG_HOST está configurado.

Uso:
    SYSLOG_HOST=siem.example.com
    SYSLOG_PORT=514   (opcional, por defecto 514)

    forwarder = SyslogForwarder(SyslogConfig(host=SYSLOG_HOST, port=SYSLOG_PORT))
    forensic.register_learning_callback(forwarder.on_incident_closed)
"""

import logging
import logging.handlers
import socket
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Mapeo del nivel de amenaza de AEGIS (Capa 7 ThreatScorer) a severidad
# estándar de syslog (RFC 5424 §6.2.1).
_SEVERITY_MAP = {
    "CRÍTICO": logging.CRITICAL,   # syslog: Critical (2)
    "ALTO":    logging.ERROR,      # syslog: Error (3)
    "MEDIO":   logging.WARNING,    # syslog: Warning (4)
    "BAJO":    logging.INFO,       # syslog: Informational (6)
}


@dataclass
class SyslogConfig:
    host: Optional[str] = None
    port: int = 514
    enabled: bool = True
    facility: int = logging.handlers.SysLogHandler.LOG_USER


class SyslogForwarder:
    """Capa 7 (forensic) → syslog-ng/rsyslog externo, apagado por defecto (SYSLOG_HOST vacío)."""

    def __init__(self, config: SyslogConfig):
        self._cfg = config
        self._logger: Optional[logging.Logger] = None

        if self._cfg.enabled and self._cfg.host:
            self._logger = self._build_logger()

    def _build_logger(self) -> logging.Logger:
        syslog_logger = logging.getLogger("aegis.syslog_forward")
        syslog_logger.setLevel(logging.INFO)
        syslog_logger.propagate = False

        handler = logging.handlers.SysLogHandler(
            address=(self._cfg.host, self._cfg.port),
            facility=self._cfg.facility,
            socktype=socket.SOCK_DGRAM,  # UDP — sin buffering ni reintento en v1
        )
        # Cabecera RFC 5424 simplificada: APP-NAME=AEGIS, resto como texto.
        handler.setFormatter(logging.Formatter(
            "AEGIS[%(process)d]: %(message)s"
        ))
        syslog_logger.addHandler(handler)
        logger.info(f"[SYSLOG] Forwarder activo → {self._cfg.host}:{self._cfg.port} (UDP)")
        return syslog_logger

    async def on_incident_closed(self, profile) -> None:
        """
        Callback registrable en AegisForensic.register_learning_callback().

        No bloquea: SysLogHandler sobre UDP es no-bloqueante por diseño
        (fire-and-forget de socket), y cualquier fallo de red se captura
        y se descarta sin propagarse a la ruta de detección.
        """
        if not self._logger:
            return

        try:
            assessment = getattr(profile, "threat_assessment", {}) or {}
            severity = assessment.get("level", "BAJO")
            level = _SEVERITY_MAP.get(severity, logging.WARNING)

            ips = ", ".join(profile.source_ips) if profile.source_ips else "desconocida"
            techniques = ",".join(getattr(t, "value", str(t)) for t in profile.techniques)

            msg = (
                f"incident_id={profile.incident_id} "
                f"severity={severity} "
                f"actor={getattr(profile.actor_type, 'value', profile.actor_type)} "
                f"intent={getattr(profile.intent, 'value', profile.intent)} "
                f"source_ip=\"{ips}\" "
                f"techniques=\"{techniques}\" "
                f"score={assessment.get('score', 'NA')}"
            )
            self._logger.log(level, msg)
        except Exception as e:
            logger.warning(f"[SYSLOG] Error reenviando incidente: {e}")
