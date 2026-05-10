from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional


class DdosDetector:
    """Heuristic DDoS detection: rate-based spikes by destination IP."""

    def __init__(self, logger) -> None:
        self.logger = logger
        self.window_seconds = 5
        self.threshold_pps = 200  # packets per second heuristic
        self.dst_window: Dict[str, deque] = defaultdict(deque)  # dst_ip -> timestamps

    def inspect(self, pkt, basics: Dict[str, Any], tls: Dict[str, Any], dns: Dict[str, Any], http: Dict[str, Any], anomaly_score: float) -> Optional[str]:
        dst = basics.get("dst")
        if not dst:
            return None

        now = time.time()
        q = self.dst_window[dst]
        q.append(now)

        while q and (now - q[0]) > self.window_seconds:
            q.popleft()

        # Estimate packets per second
        if len(q) >= max(10, int(self.threshold_pps * (self.window_seconds / self.window_seconds))):
            self.dst_window[dst].clear()
            return f"Possible DDoS Activity Detected | DEST IP: {dst} | rate_window_count={len(q)}"

        return None

