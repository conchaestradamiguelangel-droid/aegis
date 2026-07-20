"""
AEGIS — Baseline Poisoning Guard (Issue #20)
=============================================
Detects adversarial gradual baseline poisoning in the C8 Learning layer.

An attacker who understands AEGIS's adaptive thresholds can slowly
inject "normal" traffic that teaches C8 to lower its guard. This module
watches baseline update sequences for statistical anomalies.

Detection strategy:
  - Track each metric's rolling update history
  - Alert if the derivative (rate-of-change) itself is trending
    consistently in one direction for POISON_STREAK updates
  - Alert if a single update moves the baseline by more than JUMP_THRESHOLD
"""

import logging
import statistics
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Callable

logger = logging.getLogger("aegis.baseline_guard")

HISTORY_LEN      = 50     # updates to keep per metric
POISON_STREAK    = 8      # consecutive same-direction updates to flag
JUMP_THRESHOLD   = 0.40   # single update > 40% change flags immediately


@dataclass
class MetricHistory:
    name: str
    values: deque = field(default_factory=lambda: deque(maxlen=HISTORY_LEN))
    deltas: deque = field(default_factory=lambda: deque(maxlen=HISTORY_LEN))

    def update(self, new_value: float) -> tuple[bool, str]:
        """
        Record a new baseline value. Returns (poisoning_detected, reason).
        """
        if self.values:
            prev = self.values[-1]
            if prev != 0:
                delta = (new_value - prev) / abs(prev)
                self.deltas.append(delta)

                # Jump check
                if abs(delta) > JUMP_THRESHOLD:
                    self.values.append(new_value)
                    return True, f"jump: {prev:.4f} -> {new_value:.4f} ({delta*100:.1f}%)"

                # Streak check: POISON_STREAK consecutive same-direction deltas
                if len(self.deltas) >= POISON_STREAK:
                    recent = list(self.deltas)[-POISON_STREAK:]
                    if all(d > 0 for d in recent) or all(d < 0 for d in recent):
                        direction = "up" if recent[-1] > 0 else "down"
                        mean_delta = statistics.mean(recent)
                        self.values.append(new_value)
                        return True, (
                            f"streak: {POISON_STREAK} consecutive {direction} updates, "
                            f"mean delta={mean_delta*100:.2f}%/update"
                        )

        self.values.append(new_value)
        return False, ""


class BaselinePoisonGuard:
    """
    Attach to the C8 Learning layer. Call observe(metric, value) on every
    baseline update. Set on_poison_detected to receive alerts.
    """

    def __init__(self, on_poison_detected: Optional[Callable] = None):
        self._metrics: dict[str, MetricHistory] = {}
        self.on_poison_detected = on_poison_detected
        self._detections = 0

    def observe(self, metric: str, value: float) -> bool:
        """
        Record a baseline update. Returns True if poisoning is suspected.
        """
        if metric not in self._metrics:
            self._metrics[metric] = MetricHistory(name=metric)

        detected, reason = self._metrics[metric].update(value)
        if detected:
            self._detections += 1
            logger.warning(
                f"[BASELINE_GUARD] Possible poisoning on metric '{metric}': {reason} "
                f"(detection #{self._detections})"
            )
            if self.on_poison_detected:
                self.on_poison_detected(metric, value, reason)
        return detected

    @property
    def total_detections(self) -> int:
        return self._detections

    def stats(self) -> dict:
        return {
            "tracked_metrics": len(self._metrics),
            "total_detections": self._detections,
            "metrics": {k: {
                "samples": len(v.values),
                "last_value": list(v.values)[-1] if v.values else None,
            } for k, v in self._metrics.items()}
        }
