from __future__ import annotations

import os
from typing import Dict, Any

import pyshark

from utils.logger import AppLogger
from utils.colors import Colors

from parser.tls_parser import TLSParser
from parser.dns_parser import DNSParser
from parser.http_parser import HTTPParser


class PacketParser:
    def __init__(self, logger: AppLogger) -> None:
        self.logger = logger
        self.tls_parser = TLSParser()
        self.dns_parser = DNSParser()
        self.http_parser = HTTPParser()

    def _packet_basics(self, pkt) -> Dict[str, Any]:
        src = getattr(getattr(pkt, "ip", None), "src", None) or getattr(getattr(pkt, "ipv6", None), "src", None)
        dst = getattr(getattr(pkt, "ip", None), "dst", None) or getattr(getattr(pkt, "ipv6", None), "dst", None)
        proto = getattr(pkt, "transport_layer", None) or getattr(pkt, "highest_layer", None) or "UNKNOWN"
        length = getattr(pkt, "length", None)
        ts = getattr(pkt, "sniff_time", None) or getattr(pkt, "time", None)
        # Some fields are objects; cast defensively
        return {
            "src": str(src) if src is not None else None,
            "dst": str(dst) if dst is not None else None,
            "proto": str(proto) if proto is not None else None,
            "len": int(length) if length is not None and str(length).isdigit() else None,
            "ts": str(ts) if ts is not None else None,
        }

    def _print_packet_summary(self, basics: Dict[str, Any], tls: Dict[str, Any], dns: Dict[str, Any]) -> None:
        # Minimal real-time terminal output
        print(Colors.CYAN + "\n[PACKET]" + Colors.RESET)
        print(f"SRC: {basics.get('src')}")
        print(f"DST: {basics.get('dst')}")
        print(f"PROTO: {basics.get('proto')}")
        if basics.get("len") is not None:
            print(f"LEN: {basics.get('len')}")
        if tls:
            print(Colors.GREEN + "\n[TLS]" + Colors.RESET)
            for k, v in tls.items():
                print(f"{k.upper()}: {v}")
        if dns:
            print(Colors.YELLOW + "\n[DNS]" + Colors.RESET)
            for k, v in dns.items():
                print(f"{k.upper()}: {v}")

    def handle_packet(self, pkt, detectors: Dict[str, Any], ml) -> None:
        basics = self._packet_basics(pkt)
        tls = self.tls_parser.parse(pkt)
        dns = self.dns_parser.parse(pkt)
        http = self.http_parser.parse(pkt)

        # Packet log
        self.logger.log_packet(
            f"{basics['ts']} | {basics['src']} -> {basics['dst']} | {basics['proto']} | len={basics.get('len')} | tls={bool(tls)} dns={bool(dns)} http={bool(http)}"
        )

        if tls:
            self.logger.log_tls(f"{basics['ts']} | {basics['src']} -> {basics['dst']} | {tls}")

        # ML features: use simple numeric proxies
        features = {
            "packet_len": basics.get("len") or 0,
            "has_tls": 1 if tls else 0,
            "has_dns": 1 if dns else 0,
            "has_http": 1 if http else 0,
        }
        anomaly_score = ml.score(features) if ml is not None else 0.0

        # Run detectors
        for det in detectors.values():
            alert_msg = det.inspect(pkt, basics=basics, tls=tls, dns=dns, http=http, anomaly_score=anomaly_score)
            if alert_msg:
                self.logger.log_alert(alert_msg)
                print(Colors.RED + "\n[ALERT]" + Colors.RESET)
                print(alert_msg)

        # Print summary (defensive; avoid too much output)
        if tls or dns or http:
            self._print_packet_summary(basics, tls, dns)

    def parse_pcap(self, pcap_path: str, detectors: Dict[str, Any], ml) -> None:
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        cap = pyshark.FileCapture(pcap_path, keep_packets=False)
        for pkt in cap:
            try:
                self.handle_packet(pkt, detectors=detectors, ml=ml)
            except Exception:
                continue
        try:
            cap.close()
        except Exception:
            pass

