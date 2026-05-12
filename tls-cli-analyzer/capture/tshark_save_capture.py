from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class TsharkSaveCapture:
    """Capture traffic with tshark and save it to a PCAP/PCAPNG file.

    This is used for the project requirement:
    - execute capture for a fixed duration
    - save the packet package (pcap) to disk
    """

    interface: str
    duration_seconds: int
    pcap_out: str

    def run(self) -> None:
        tshark_path = shutil.which("tshark")
        if not tshark_path:
            raise RuntimeError(
                "tshark not found. Install Wireshark/tshark or run in an environment where tshark is available."
            )

        # -a duration:<seconds> stops capture after duration.
        # -w writes packets to file.
        cmd = [
            tshark_path,
            "-i",
            self.interface,
            "-a",
            f"duration:{int(self.duration_seconds)}",
            "-w",
            self.pcap_out,
        ]

        # Best-effort: do not force text streaming; keep it silent.
        # If tshark fails, subprocess.run will raise.
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

