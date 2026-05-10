from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Any

import pyshark


@dataclass
class TsharkCapture:
    interface: str
    duration_seconds: int

    def run(self, parser, detectors: Dict[str, Any], ml) -> None:
        # pyshark supports tshark backend automatically, but this class keeps the option.
        cap = pyshark.LiveCapture(interface=self.interface, only_summaries=False)
        start = time.time()

        for pkt in cap:
            if (time.time() - start) > self.duration_seconds:
                break
            try:
                parser.handle_packet(pkt, detectors=detectors, ml=ml)
            except Exception:
                continue

        try:
            cap.close()
        except Exception:
            pass

