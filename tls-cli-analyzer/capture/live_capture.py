from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Any

import pyshark

from utils.logger import AppLogger


@dataclass
class LiveCapture:
    interface: str
    duration_seconds: int

    def run(self, parser, detectors: Dict[str, Any], ml) -> None:
        """Start live capture using pyshark/tshark under the hood."""
        cap = pyshark.LiveCapture(interface=self.interface, only_summaries=False)
        start = time.time()

        for pkt in cap:
            # Stop by duration
            if (time.time() - start) > self.duration_seconds:
                break

            try:
                parser.handle_packet(pkt, detectors=detectors, ml=ml)
            except Exception:
                # Defensive: never crash the capture loop
                continue

        # Best effort cleanup
        try:
            cap.close()
        except Exception:
            pass

