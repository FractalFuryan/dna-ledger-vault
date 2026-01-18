"""
Non-behavioral system metrics.

⭕️🛑 Privacy boundary:
- No user identifiers
- No content metrics
- No session tracking
- System health only
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class Metrics:
    """
    Non-behavioral system metrics only.
    
    Tracks infrastructure health, not user behavior.
    Safe for observability without privacy leakage.
    """

    counters: Dict[str, int] = field(default_factory=dict)
    gauges: Dict[str, float] = field(default_factory=dict)

    def inc(self, name: str, by: int = 1) -> None:
        """Increment counter by value."""
        self.counters[name] = self.counters.get(name, 0) + by

    def observe(self, name: str, value: float) -> None:
        """Record gauge value."""
        self.gauges[name] = float(value)

    def snapshot(self) -> dict:
        """Return current metrics snapshot."""
        return {
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
        }
