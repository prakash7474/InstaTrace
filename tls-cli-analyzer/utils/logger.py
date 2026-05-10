from __future__ import annotations

import logging
import os
from dataclasses import dataclass


@dataclass
class AppLogger:
    base_dir: str

    def __post_init__(self) -> None:
        self.packets_log_path = os.path.join(self.base_dir, "logs", "packets.log")
        self.alerts_log_path = os.path.join(self.base_dir, "logs", "alerts.log")
        self.tls_log_path = os.path.join(self.base_dir, "logs", "tls.log")

        self._packets_logger = self._make_logger("packets", self.packets_log_path)
        self._alerts_logger = self._make_logger("alerts", self.alerts_log_path)
        self._tls_logger = self._make_logger("tls", self.tls_log_path)

    def _make_logger(self, name: str, path: str) -> logging.Logger:
        logger = logging.getLogger(f"{name}:{path}")
        logger.setLevel(logging.INFO)
        logger.propagate = False

        # Avoid duplicate handlers when re-instantiating
        if not logger.handlers:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            fh = logging.FileHandler(path, encoding="utf-8")
            fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        return logger

    def log_packet(self, msg: str) -> None:
        self._packets_logger.info(msg)

    def log_alert(self, msg: str) -> None:
        self._alerts_logger.warning(msg)

    def log_tls(self, msg: str) -> None:
        self._tls_logger.info(msg)


