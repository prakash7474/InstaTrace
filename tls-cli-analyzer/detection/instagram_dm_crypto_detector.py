from __future__ import annotations

import os
from typing import Any, Dict, Optional

from crypto.instagram_dm_encryptor import InstagramDMEncryptor


class InstagramDMCryptoDetector:
    """Metadata-only demo trigger for Instagram-like DMs.

    This detector does NOT decrypt real Instagram traffic.
    When a heuristic matches, it runs the local AES-256-GCM encrypt/decrypt
    demo (for verification) and logs the result.
    """

    def __init__(
        self,
        logger,
        plaintext_demo: str = "Hello, this is a secret DM!",
        min_http_matches: int = 1,
        require_tls: bool = True,
        max_alerts_per_minute: int = 5,
    ) -> None:
        self.logger = logger
        self.plaintext_demo = plaintext_demo
        self.min_http_matches = min_http_matches
        self.require_tls = require_tls
        self.max_alerts_per_minute = max_alerts_per_minute

        self._tally_window_seconds = 60
        self._recent_alert_times: list[float] = []

        self._encryptor = InstagramDMEncryptor()

    @staticmethod
    def _normalize(s: Any) -> str:
        return str(s or "").lower()

    def _http_score(self, http: Dict[str, Any]) -> int:
        host = self._normalize(http.get("host"))
        path = self._normalize(http.get("path"))

        keywords = [
            "instagram",
            "i.instagram",
            "facebook",
            "graph",
            "messages",
            "direct",
            "inbox",
            "thread",
            "dm",
            "/direct",
            "message",
        ]

        score = 0
        haystack = " ".join([host, path])
        for kw in keywords:
            if kw in haystack:
                score += 1
        return score

    def _rate_limited(self) -> bool:
        import time

        now = time.time()
        # drop old
        self._recent_alert_times = [t for t in self._recent_alert_times if (now - t) <= self._tally_window_seconds]
        if len(self._recent_alert_times) >= self.max_alerts_per_minute:
            return True
        return False

    def inspect(
        self,
        pkt,
        basics: Dict[str, Any],
        tls: Dict[str, Any],
        dns: Dict[str, Any],
        http: Dict[str, Any],
        anomaly_score: float,
    ) -> Optional[str]:
        if self.require_tls and not tls:
            return None

        if not http:
            return None

        http_score = self._http_score(http)
        if http_score < self.min_http_matches:
            return None

        if self._rate_limited():
            return None

        result = self._encryptor.full_process(self.plaintext_demo, verify=True)

        import time

        self._recent_alert_times.append(time.time())

        msg = (
            "Instagram DM crypto demo triggered | "
            f"src={basics.get('src')} dst={basics.get('dst')} | "
            f"http_host={http.get('host')} http_path={http.get('path')} | "
            f"http_keyword_score={http_score} | "
            f"nonce_b64={result.nonce_b64} | "
            f"ciphertext_b64={result.ciphertext_b64} | "
            f"decrypted_message_text={result.decrypted_message_text!r} | "
            f"decrypt_ok={result.decrypted_message_text == self.plaintext_demo}"
        )



        # Log locally into alerts.log (detectors are expected to return the string)
        try:
            self.logger.log_alert(msg)
        except Exception:
            pass

        return msg

