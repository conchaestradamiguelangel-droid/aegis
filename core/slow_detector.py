"""
AEGIS — Low-and-Slow Attack Detector (Issue #19)
=================================================
Detects attackers who stay below per-request thresholds by spreading
activity over long time windows (hours, not seconds).

Strategy:
  - Maintain a sliding 1-hour counter per IP
  - Compare hourly rate against a 24h rolling baseline
  - Alert if rate drifts above baseline by DRIFT_FACTOR for > MIN_DRIFT_WINDOWS
"""

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Callable

logger = logging.getLogger("aegis.slow_detector")

WINDOW_S        = 3600      # 1-hour window
BASELINE_HOURS  = 24        # rolling baseline length
DRIFT_FACTOR    = 2.5       # alert if hourly rate > 2.5x baseline mean
MIN_DRIFT_WINDOWS = 2       # require 2+ consecutive drifting hours to avoid noise


@dataclass
class SlowProfile:
    ip: str
    hourly_buckets: deque = field(default_factory=lambda: deque(maxlen=BASELINE_HOURS))
    current_bucket_start: float = field(default_factory=time.monotonic)
    current_bucket_count: int = 0
    drift_count: int = 0

    def record_request(self, ts: float = None) -> None:
        now = ts or time.monotonic()
        if now - self.current_bucket_start >= WINDOW_S:
            self.hourly_buckets.append(self.current_bucket_count)
            self.current_bucket_count = 0
            self.current_bucket_start = now
        self.current_bucket_count += 1

    def baseline_mean(self) -> float:
        if not self.hourly_buckets:
            return 0.0
        return sum(self.hourly_buckets) / len(self.hourly_buckets)

    def is_drifting(self) -> bool:
        mean = self.baseline_mean()
        if mean < 5:          # too sparse to judge
            return False
        return self.current_bucket_count > mean * DRIFT_FACTOR


class LowAndSlowDetector:
    """
    Wraps the existing ActiveAgent to add long-window drift detection.
    Call record(ip) on every incoming request and set on_alert to receive
    detections.
    """

    def __init__(self, on_alert: Optional[Callable] = None):
        self._profiles: dict[str, SlowProfile] = {}
        self.on_alert = on_alert
        self._total_detections = 0

    def record(self, ip: str, ts: float = None) -> bool:
        """
        Record a request from ip. Returns True if a low-and-slow alert fires.
        """
        if ip not in self._profiles:
            self._profiles[ip] = SlowProfile(ip=ip)
        profile = self._profiles[ip]
        profile.record_request(ts)

        if profile.is_drifting():
            profile.drift_count += 1
        else:
            profile.drift_count = max(0, profile.drift_count - 1)

        if profile.drift_count >= MIN_DRIFT_WINDOWS:
            mean = profile.baseline_mean()
            current = profile.current_bucket_count
            logger.warning(
                f"[SLOW_DETECT] {ip} low-and-slow: {current} req/h vs baseline {mean:.1f} req/h "
                f"(factor {current/mean:.1f}x) — drift_count={profile.drift_count}"
            )
            self._total_detections += 1
            if self.on_alert:
                self.on_alert(ip, current, mean, profile.drift_count)
            return True
        return False

    def evict_stale(self, max_idle_hours: int = 48) -> int:
        """Remove IPs not seen for max_idle_hours. Returns count evicted."""
        now = time.monotonic()
        cutoff = now - (max_idle_hours * 3600)
        stale = [ip for ip, p in self._profiles.items() if p.current_bucket_start < cutoff]
        for ip in stale:
            del self._profiles[ip]
        return len(stale)

    @property
    def total_detections(self) -> int:
        return self._total_detections

    def stats(self) -> dict:
        return {
            "tracked_ips": len(self._profiles),
            "total_detections": self._total_detections,
        }
