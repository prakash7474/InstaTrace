from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Any, Dict, Optional

from utils.colors import Colors


class PortscanDetector:
    """Heuristic portscan detection (metadata only)."""

    def __init__(self, logger) -> None:
        self.logger = logger
        self.window_seconds = 10
        self.threshold_ports = 20
        self.seen_ports: Dict[str, deque] = defaultdict(deque)  # src_ip -> (ts, dst_port)

    def inspect(self, pkt, basics: Dict[str, Any], tls: Dict[str, Any], dns: Dict[str, Any], http: Dict[str, Any], anomaly_score: float) -> Optional[str]:
        src = basics.get("src")
        if not src:
            return None

        # Try to get destination port
        dst_port = None
        if hasattr(pkt, "tcp"):
            dst_port = getattr(pkt.tcp, "dstport", None)
        elif hasattr(pkt, "udp"):
            dst_port = getattr(pkt.udp, "dstport", None)

        if not dst_port:
            return None

        now = time.time()
        q = self.seen_ports[src]
        q.append((now, str(dst_port)))

        # Drop old
        while q and (now - q[0][0]) > self.window_seconds:
            q.popleft()

        unique_ports = {p for _, p in q}
        if len(unique_ports) >= self.threshold_ports:
            self.seen_ports[src].clear()
            return f"Possible Port Scan Detected | SOURCE IP: {src} | unique_dst_ports={len(unique_ports)}"

        return None

