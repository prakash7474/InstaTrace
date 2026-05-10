from __future__ import annotations

from typing import Dict, Any


class HTTPParser:
    def parse(self, pkt) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        if hasattr(pkt, "http"):
            http = pkt.http
            data["method"] = getattr(http, "request_method", None)
            data["host"] = getattr(http, "host", None)
            data["path"] = getattr(http, "request_uri", None)
            sc = getattr(http, "response_code", None)
            data["status_code"] = sc
        # Remove Nones
        return {k: v for k, v in data.items() if v is not None}

