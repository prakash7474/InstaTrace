from __future__ import annotations

from typing import Dict, Any


class DNSParser:
    def parse(self, pkt) -> Dict[str, Any]:
        data: Dict[str, Any] = {}
        if hasattr(pkt, "dns"):
            dns = pkt.dns
            # queries
            q = getattr(dns, "qry_name", None) or getattr(dns, "query_name", None)
            data["query"] = q
            # responses may contain multiple IPs
            resp = getattr(dns, "a", None) or getattr(dns, "answers", None)
            # Some pyshark fields stringify poorly; keep best-effort raw
            if resp is not None:
                data["response_ips"] = str(resp)
        return {k: v for k, v in data.items() if v is not None}

