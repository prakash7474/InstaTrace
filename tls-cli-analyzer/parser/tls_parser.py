from __future__ import annotations

from typing import Dict, Any


class TLSParser:
    """Extract TLS metadata from a packet if present (metadata only; no decryption)."""

    def parse(self, pkt) -> Dict[str, Any]:
        data: Dict[str, Any] = {}

        # pyshark layers vary; attempt common TLS layer attributes
        if hasattr(pkt, "tls"):
            tls = pkt.tls
            # Use getattr defensively; not all fields exist
            data["tls_version"] = getattr(tls, "handshake_version", None) or getattr(tls, "version", None)
            data["cipher_suite"] = getattr(tls, "handshake_ciphersuite", None) or getattr(tls, "ciphersuite", None)
            data["sni"] = getattr(tls, "handshake_extensions_server_name", None) or getattr(tls, "server_name", None)
            data["handshake_type"] = getattr(tls, "handshake_type", None)

        return {k: v for k, v in data.items() if v is not None}

