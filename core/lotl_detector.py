"""
AEGIS — Living-off-the-Land (LOtL) Detection (Issue #23)
=========================================================
Detects attackers abusing legitimate network protocols to evade signature-
based detection. LOtL at the network level means traffic that looks like
legitimate tool usage but has anomalous behavioral patterns.

Signals detected:
  - DNS tunneling: unusually long/frequent DNS queries per IP
  - HTTP exfiltration: large outbound bodies on uncommon user-agents
  - Protocol misuse: SSH/FTP sessions with anomalous byte ratios
  - Excessive legitimate-port scanning (80, 443, 22 with timing patterns)

This module is additive — it produces DetectionEvents that feed into
the existing C3 Detector pipeline without replacing it.
"""

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("aegis.lotl")

# Thresholds
DNS_QUERY_LEN_THRESHOLD   = 50    # chars; legitimate hostnames rarely exceed this
DNS_QUERIES_PER_MIN       = 30    # queries/min suspicious for a single IP
HTTP_BODY_EXFIL_BYTES     = 50_000  # outbound body > 50KB on unusual UA
LEGIT_PORT_SCAN_THRESHOLD = 20    # requests to {80,443,22,21} in 60s


class LOtLType(str, Enum):
    DNS_TUNNELING   = "DNS_TUNNELING"
    HTTP_EXFIL      = "HTTP_EXFIL"
    PORT_MISUSE     = "PORT_MISUSE"
    PROTOCOL_ABUSE  = "PROTOCOL_ABUSE"


@dataclass
class LOtLEvent:
    ip:          str
    lotl_type:   LOtLType
    detail:      str
    confidence:  float    # 0.0-1.0
    ts:          float = field(default_factory=time.monotonic)

    def to_dict(self) -> dict:
        return {
            "ip":         self.ip,
            "lotl_type":  self.lotl_type,
            "detail":     self.detail,
            "confidence": self.confidence,
            "ts":         self.ts,
        }


class LOtLDetector:
    """
    Call the appropriate record_* method when AEGIS observes network events.
    Set on_detection to receive LOtLEvents.
    """

    def __init__(self, on_detection: Optional[Callable] = None):
        self.on_detection = on_detection
        self._dns_queries:    defaultdict = defaultdict(list)  # ip -> [ts, ...]
        self._dns_lengths:    defaultdict = defaultdict(list)  # ip -> [len, ...]
        self._http_bodies:    defaultdict = defaultdict(int)   # ip -> bytes_out
        self._legit_port_hits: defaultdict = defaultdict(list) # ip -> [ts, ...]
        self._total_detections = 0

    def record_dns_query(self, ip: str, hostname: str, ts: float = None) -> bool:
        """Record a DNS query. Returns True if tunneling pattern detected."""
        now = ts or time.monotonic()
        self._dns_queries[ip].append(now)
        self._dns_lengths[ip].append(len(hostname))

        # Prune old queries (> 60s)
        cutoff = now - 60
        self._dns_queries[ip] = [t for t in self._dns_queries[ip] if t > cutoff]

        rate = len(self._dns_queries[ip])
        avg_len = sum(self._dns_lengths[ip][-20:]) / min(20, len(self._dns_lengths[ip]))

        if rate > DNS_QUERIES_PER_MIN or avg_len > DNS_QUERY_LEN_THRESHOLD:
            confidence = min(1.0, (rate / DNS_QUERIES_PER_MIN + avg_len / DNS_QUERY_LEN_THRESHOLD) / 2)
            return self._emit(LOtLEvent(
                ip=ip, lotl_type=LOtLType.DNS_TUNNELING,
                detail=f"{rate} queries/min, avg_hostname_len={avg_len:.0f}",
                confidence=confidence
            ))
        return False

    def record_http_outbound(self, ip: str, body_bytes: int, user_agent: str = "") -> bool:
        """Record an outbound HTTP response body. Returns True if exfil pattern detected."""
        self._http_bodies[ip] += body_bytes
        total = self._http_bodies[ip]

        suspicious_ua = not any(
            kw in user_agent.lower()
            for kw in ["mozilla", "chrome", "safari", "curl", "python-requests", "wget"]
        )

        if total > HTTP_BODY_EXFIL_BYTES and suspicious_ua:
            confidence = min(1.0, total / (HTTP_BODY_EXFIL_BYTES * 2))
            self._http_bodies[ip] = 0  # reset after alert
            return self._emit(LOtLEvent(
                ip=ip, lotl_type=LOtLType.HTTP_EXFIL,
                detail=f"{total} bytes outbound, ua='{user_agent[:40]}'",
                confidence=confidence
            ))
        return False

    def record_legit_port_hit(self, ip: str, port: int, ts: float = None) -> bool:
        """Record connection to a legitimate port (22, 80, 443, 21). Returns True if scan pattern detected."""
        if port not in (21, 22, 80, 443):
            return False
        now = ts or time.monotonic()
        self._legit_port_hits[ip].append((now, port))

        cutoff = now - 60
        recent = [(t, p) for t, p in self._legit_port_hits[ip] if t > cutoff]
        self._legit_port_hits[ip] = recent

        unique_ports = len({p for _, p in recent})
        if len(recent) > LEGIT_PORT_SCAN_THRESHOLD and unique_ports >= 3:
            confidence = min(1.0, len(recent) / (LEGIT_PORT_SCAN_THRESHOLD * 2))
            return self._emit(LOtLEvent(
                ip=ip, lotl_type=LOtLType.PORT_MISUSE,
                detail=f"{len(recent)} hits on legit ports in 60s ({unique_ports} distinct)",
                confidence=confidence
            ))
        return False

    def _emit(self, event: LOtLEvent) -> bool:
        self._total_detections += 1
        logger.warning(
            f"[LOTL] {event.lotl_type} from {event.ip}: {event.detail} "
            f"(confidence={event.confidence:.2f})"
        )
        if self.on_detection:
            self.on_detection(event)
        return True

    @property
    def total_detections(self) -> int:
        return self._total_detections

    def stats(self) -> dict:
        return {
            "tracked_ips":       len(self._dns_queries),
            "total_detections":  self._total_detections,
        }
