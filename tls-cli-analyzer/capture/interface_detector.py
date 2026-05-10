from __future__ import annotations

import psutil


def detect_capture_interface() -> str:
    """Return a likely default network interface for packet capture."""
    addrs = psutil.net_if_addrs()
    for name, addr_list in addrs.items():
        for a in addr_list:
            if getattr(a, "family", None) is not None and str(a.family).lower().endswith("address_family.inet"):
                return name
    # Fallback: first interface
    return next(iter(addrs.keys()))

