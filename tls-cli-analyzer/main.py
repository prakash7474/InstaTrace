#!/usr/bin/env python3
"""Secure TLS Traffic Analyzer CLI (educational/defensive, authorized environments only).

This file contains the CLI + main menu loop.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from utils.banner import print_banner
from utils.logger import AppLogger
from utils.colors import Colors

from capture.interface_detector import detect_capture_interface
from capture.live_capture import LiveCapture
from capture.tshark_capture import TsharkCapture
from parser.packet_parser import PacketParser
from detection.portscan_detector import PortscanDetector
from detection.ddos_detector import DdosDetector
from detection.anomaly_detector import AnomalyDetector
from crypto.instagram_dm_encryptor import InstagramDMEncryptor



def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="Secure TLS Traffic Analyzer CLI",
        description="Live packet monitoring + defensive TLS/DNS/HTTP metadata analysis.",
    )
    sub = p.add_subparsers(dest="command", required=False)

    # live
    p_live = sub.add_parser("live", help="Start live capture + real-time analysis")
    p_live.add_argument("--iface", default=None, help="Network interface name (optional)")
    p_live.add_argument("--time", type=int, default=60, help="Capture duration seconds")
    p_live.add_argument("--use-tshark", action="store_true", help="Use tshark for capture")

    # pcap
    p_pcap = sub.add_parser("pcap", help="Analyze an offline PCAP file")
    p_pcap.add_argument("--pcap", required=True, help="Path to pcap file")

    # alerts
    sub.add_parser("alerts", help="Show alerts log")

    # export
    p_export = sub.add_parser("export", help="Export a text report")
    p_export.add_argument("--out", default="./reports/report.txt", help="Output report path")

    # train-ml
    sub.add_parser("train-ml", help="Train and persist an Isolation Forest model")

    # dm-crypto-verify (metadata-based integration trigger demo)
    p_dm = sub.add_parser(
        "dm-crypto-verify",
        help="Run local Instagram-like DM AES-256-GCM encrypt/decrypt verification",
    )
    p_dm.add_argument("--text", default="Hello, this is a secret DM!", help="Message text to encrypt")

    return p



def ensure_dirs() -> None:
    for d in ["logs", "reports", "pcaps"]:
        os.makedirs(d, exist_ok=True)


def run_alerts(logger: AppLogger) -> int:
    alerts_path = logger.alerts_log_path
    if not os.path.exists(alerts_path):
        print(f"{Colors.YELLOW}No alerts log found:{Colors.RESET} {alerts_path}")
        return 0
    with open(alerts_path, "r", encoding="utf-8", errors="ignore") as f:
        print(f.read())
    return 0


def export_report(logger: AppLogger, out_path: str) -> int:
    os.makedirs(os.path.dirname(out_path) or "./reports", exist_ok=True)

    packet_count = 0
    tls_count = 0
    alerts_count = 0

    if os.path.exists(logger.packets_log_path):
        with open(logger.packets_log_path, "r", encoding="utf-8", errors="ignore") as f:
            packet_count = sum(1 for _ in f)

    if os.path.exists(logger.tls_log_path):
        with open(logger.tls_log_path, "r", encoding="utf-8", errors="ignore") as f:
            tls_count = sum(1 for _ in f)

    if os.path.exists(logger.alerts_log_path):
        with open(logger.alerts_log_path, "r", encoding="utf-8", errors="ignore") as f:
            alerts_count = sum(1 for _ in f)

    with open(out_path, "w", encoding="utf-8") as out:
        out.write("Secure TLS Traffic Analyzer CLI - Export\n")
        out.write("=" * 50 + "\n")
        out.write(f"Packet log lines: {packet_count}\n")
        out.write(f"TLS log lines: {tls_count}\n")
        out.write(f"Alerts log lines: {alerts_count}\n")
        out.write("\n")
        out.write("[ALERTS SAMPLE]\n")
        if os.path.exists(logger.alerts_log_path):
            with open(logger.alerts_log_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            out.writelines(lines[-200:])

    print(f"{Colors.GREEN}[+] Report exported to:{Colors.RESET} {out_path}")
    return 0


def run_menu(args: argparse.Namespace, logger: AppLogger) -> int:
    # Real-time menu loop
    print_banner()

    while True:
        print(f"{Colors.CYAN}Main Menu{Colors.RESET}")
        print(f"1) {Colors.BLUE}Live Capture{Colors.RESET}")
        print(f"2) {Colors.BLUE}Analyze PCAP{Colors.RESET}")
        print(f"3) {Colors.BLUE}View Alerts{Colors.RESET}")
        print(f"4) {Colors.BLUE}Export Report{Colors.RESET}")
        print(f"5) {Colors.BLUE}Train ML Model{Colors.RESET}")
        print(f"6) {Colors.BLUE}Exit{Colors.RESET}")

        choice = input(f"{Colors.YELLOW}Select option (1-6): {Colors.RESET}").strip()
        if choice == "1":
            iface = detect_capture_interface() if not args.iface else args.iface
            if args.use_tshark:
                cap = TsharkCapture(interface=iface, duration_seconds=args.time)
            else:
                cap = LiveCapture(interface=iface, duration_seconds=args.time)
            parser = PacketParser(logger=logger)
            detectors = {
                "portscan": PortscanDetector(logger=logger),
                "ddos": DdosDetector(logger=logger),
            }
            ml = AnomalyDetector(logger=logger)
            cap.run(parser=parser, detectors=detectors, ml=ml)

        elif choice == "2":
            pcap_path = input("Enter PCAP path: ").strip()
            parser = PacketParser(logger=logger)
            detectors = {
                "portscan": PortscanDetector(logger=logger),
                "ddos": DdosDetector(logger=logger),
            }
            ml = AnomalyDetector(logger=logger)
            parser.parse_pcap(pcap_path, detectors=detectors, ml=ml)

        elif choice == "3":
            run_alerts(logger)

        elif choice == "4":
            out = input("Enter export output path (default ./reports/report.txt): ").strip()
            if not out:
                out = "./reports/report.txt"
            export_report(logger, out)

        elif choice == "5":
            ml = AnomalyDetector(logger=logger)
            ml.train_and_persist()

        elif choice == "6":
            print(f"{Colors.GREEN}Exiting.{Colors.RESET}")
            return 0

        else:
            print(f"{Colors.RED}Invalid choice.{Colors.RESET}")


def main(argv: Optional[list[str]] = None) -> int:
    ensure_dirs()
    args_ns = build_arg_parser().parse_args(argv)

    # Setup logger
    logger = AppLogger(base_dir=".")

    # If no subcommand provided -> interactive menu
    if args_ns.command is None:
        return run_menu(args_ns, logger)

    # Subcommand execution
    if args_ns.command == "live":
        print_banner()
        iface = detect_capture_interface() if not args_ns.iface else args_ns.iface
        cap = TsharkCapture(interface=iface, duration_seconds=args_ns.time) if args_ns.use_tshark else LiveCapture(
            interface=iface, duration_seconds=args_ns.time
        )
        parser = PacketParser(logger=logger)
        detectors = {
            "portscan": PortscanDetector(logger=logger),
            "ddos": DdosDetector(logger=logger),
        }
        ml = AnomalyDetector(logger=logger)
        cap.run(parser=parser, detectors=detectors, ml=ml)
        return 0

    if args_ns.command == "pcap":
        parser = PacketParser(logger=logger)
        detectors = {
            "portscan": PortscanDetector(logger=logger),
            "ddos": DdosDetector(logger=logger),
        }
        ml = AnomalyDetector(logger=logger)
        parser.parse_pcap(args_ns.pcap, detectors=detectors, ml=ml)
        return 0

    if args_ns.command == "alerts":
        return run_alerts(logger)

    if args_ns.command == "export":
        return export_report(logger, args_ns.out)

    if args_ns.command == "train-ml":
        ml = AnomalyDetector(logger=logger)
        ml.train_and_persist()
        return 0

    if args_ns.command == "dm-crypto-verify":
        ig_crypto = InstagramDMEncryptor()
        result = ig_crypto.full_process(args_ns.text, verify=True)
        print("\n--- DM Crypto Verification ---")
        print(f"Payload (pre-encryption): {result.payload_json}")
        print(f"Nonce (b64): {result.nonce_b64}")
        print(f"Ciphertext (b64): {result.ciphertext_b64}")
        print(f"Decrypted message_text: {result.decrypted_message_text}")
        logger.log_alert(f"DM crypto verification triggered (text={args_ns.text!r}); decrypted={result.decrypted_message_text!r}")
        return 0

    print(f"{Colors.RED}Unknown command.{Colors.RESET}")
    return 1



if __name__ == "__main__":
    raise SystemExit(main())

