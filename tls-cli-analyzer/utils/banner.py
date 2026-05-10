from __future__ import annotations

from utils.colors import Colors


def print_banner() -> None:
    line = "=" * 54
    print(Colors.CYAN + line + Colors.RESET)
    print(Colors.GREEN + " Secure TLS Traffic Analyzer " + Colors.RESET)
    print(Colors.CYAN + line + Colors.RESET)

