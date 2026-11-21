#!/usr/bin/env python3
"""
Wireless Intrusion Detection System (WIDS) for Hoover WiFi Security Toolkit
Passively monitors WiFi traffic for suspicious activity including
deauth floods, evil twins, rogue APs, karma attacks, and EAPOL anomalies
"""

import sys
import os
import argparse
import dataclasses
import json
import threading
import subprocess
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeResp, RadioTap,
)
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sniff

from utils import validate_interface, check_monitor_mode, require_root, setup_logging
from oui_lookup import lookup_vendor


@dataclasses.dataclass
class Alert:
    timestamp: str
    severity: str
    alert_type: str
    description: str
    source_mac: str
    details: dict


class WIDSMonitor:
    def __init__(self, interface: str,
                 known_aps_file: Optional[str] = None,
                 alert_callback: Optional[object] = None,
                 channel_hop: bool = True,
                 hop_interval: float = 0.5,
                 deauth_threshold: int = 10,
                 deauth_window: int = 5,
                 log_file: str = "captures/wids_alerts.json") -> None:
        self.interface: str = interface
        self.known_aps: dict[str, dict] = {}
        self.alert_callback = alert_callback
        self.channel_hop: bool = channel_hop
        self.hop_interval: float = hop_interval
        self.deauth_threshold: int = deauth_threshold
        self.deauth_window: int = deauth_window
        self.log_file: str = log_file
        self.logger = setup_logging("wids")
        self.alerts: list[Alert] = []
        self._deauth_tracker: dict[str, list[float]] = {}
        self._ap_ssid_tracker: dict[str, set[str]] = {}
        self._ssid_bssid_tracker: dict[str, set[str]] = {}
        self._eapol_tracker: dict[str, list[float]] = {}
        self._seen_aps: set[str] = set()
        self._stop_event = threading.Event()
        self._hop_running: bool = False
        self._start_time: Optional[float] = None
        self._stats: dict = {
            "packets_processed": 0,
            "beacons": 0,
            "deauths": 0,
            "eapol": 0,
            "probe_responses": 0,
        }

        if known_aps_file:
            self.load_known_aps(known_aps_file)

    def load_known_aps(self, filepath: str) -> None:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            for bssid, info in data.items():
                self.known_aps[bssid.upper()] = info
            self.logger.info("Loaded %d known APs from %s", len(self.known_aps), filepath)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.logger.error("Failed to load known APs: %s", e)

    def add_known_ap(self, bssid: str, ssid: str, channel: Optional[int] = None) -> None:
        self.known_aps[bssid.upper()] = {
            "ssid": ssid,
            "channel": channel,
        }

    def packet_handler(self, packet) -> None:
        self._stats["packets_processed"] += 1

        try:
            if packet.haslayer(Dot11Beacon):
                self._stats["beacons"] += 1
                self._check_beacon(packet)
            elif packet.haslayer(Dot11Deauth):
                self._stats["deauths"] += 1
                self._check_deauth(packet)
            elif packet.haslayer(Dot11ProbeResp):
                self._stats["probe_responses"] += 1
                self._check_probe_response(packet)

            if packet.haslayer(EAPOL):
                self._stats["eapol"] += 1
                self._check_eapol(packet)
        except Exception as e:
            self.logger.debug("Error processing packet: %s", e)

    def _extract_ssid(self, packet) -> str:
        elt = packet.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0 and elt.info:
                try:
                    return elt.info.decode("utf-8", errors="replace")
                except Exception:
                    return ""
            elt = elt.payload.getlayer(Dot11Elt)
        return ""

    def _check_beacon(self, packet) -> None:
        bssid = str(packet[Dot11].addr3 or "").upper()
        if not bssid or bssid == "FF:FF:FF:FF:FF:FF":
            return

        ssid = self._extract_ssid(packet)

        if bssid not in self._ap_ssid_tracker:
            self._ap_ssid_tracker[bssid] = set()
        self._ap_ssid_tracker[bssid].add(ssid)

        if ssid:
            if ssid not in self._ssid_bssid_tracker:
                self._ssid_bssid_tracker[ssid] = set()
            self._ssid_bssid_tracker[ssid].add(bssid)

        if bssid not in self._seen_aps:
            self._seen_aps.add(bssid)
            if bssid not in self.known_aps:
                vendor = lookup_vendor(bssid)
                self._raise_alert(
                    "MEDIUM", "ROGUE_AP",
                    f"New unknown AP detected: {bssid} (SSID: '{ssid}', Vendor: {vendor})",
                    bssid, {"ssid": ssid, "vendor": vendor},
                )

        if ssid and self.known_aps:
            known_bssids_for_ssid = {
                b for b, info in self.known_aps.items() if info.get("ssid") == ssid
            }
            if known_bssids_for_ssid and bssid not in known_bssids_for_ssid:
                self._raise_alert(
                    "HIGH", "EVIL_TWIN",
                    f"Evil Twin detected: SSID '{ssid}' from unknown BSSID {bssid} "
                    f"(known BSSIDs: {', '.join(known_bssids_for_ssid)})",
                    bssid, {"ssid": ssid, "known_bssids": list(known_bssids_for_ssid)},
                )

        if len(self._ap_ssid_tracker.get(bssid, set())) > 3:
            ssids = self._ap_ssid_tracker[bssid]
            non_empty = {s for s in ssids if s}
            if len(non_empty) > 3:
                self._raise_alert(
                    "HIGH", "KARMA_ATTACK",
                    f"Possible Karma attack: BSSID {bssid} advertising {len(non_empty)} SSIDs",
                    bssid, {"ssids": list(non_empty)},
                )

    def _check_deauth(self, packet) -> None:
        source_mac = str(packet[Dot11].addr2 or "").upper()
        if not source_mac:
            return

        now = time.time()
        if source_mac not in self._deauth_tracker:
            self._deauth_tracker[source_mac] = []

        timestamps = self._deauth_tracker[source_mac]
        timestamps.append(now)

        cutoff = now - self.deauth_window
        self._deauth_tracker[source_mac] = [t for t in timestamps if t > cutoff]
        timestamps = self._deauth_tracker[source_mac]

        if len(timestamps) > self.deauth_threshold:
            target = str(packet[Dot11].addr1 or "").upper()
            self._raise_alert(
                "CRITICAL", "DEAUTH_FLOOD",
                f"Deauth flood detected from {source_mac} "
                f"({len(timestamps)} frames in {self.deauth_window}s, target: {target})",
                source_mac,
                {"count": len(timestamps), "window": self.deauth_window, "target": target},
            )
            self._deauth_tracker[source_mac] = []

    def _check_probe_response(self, packet) -> None:
        bssid = str(packet[Dot11].addr3 or "").upper()
        if not bssid or bssid == "FF:FF:FF:FF:FF:FF":
            return

        ssid = self._extract_ssid(packet)

        if bssid not in self._ap_ssid_tracker:
            self._ap_ssid_tracker[bssid] = set()
        self._ap_ssid_tracker[bssid].add(ssid)

    def _check_eapol(self, packet) -> None:
        if not packet.haslayer(Dot11):
            return

        bssid = str(packet[Dot11].addr3 or packet[Dot11].addr2 or "").upper()
        now = time.time()

        if bssid not in self._eapol_tracker:
            self._eapol_tracker[bssid] = []

        self._eapol_tracker[bssid].append(now)

        cutoff = now - 10
        self._eapol_tracker[bssid] = [t for t in self._eapol_tracker[bssid] if t > cutoff]

        if len(self._eapol_tracker[bssid]) > 20:
            self._raise_alert(
                "HIGH", "EAPOL_ANOMALY",
                f"Unusual EAPOL activity near {bssid} "
                f"({len(self._eapol_tracker[bssid])} frames in 10s)",
                bssid,
                {"count": len(self._eapol_tracker[bssid]), "window": 10},
            )
            self._eapol_tracker[bssid] = []

    def _raise_alert(self, severity: str, alert_type: str, description: str,
                     source_mac: str, details: dict) -> None:
        alert = Alert(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            severity=severity,
            alert_type=alert_type,
            description=description,
            source_mac=source_mac,
            details=details,
        )
        self.alerts.append(alert)

        log_method = {
            "LOW": self.logger.info,
            "MEDIUM": self.logger.warning,
            "HIGH": self.logger.warning,
            "CRITICAL": self.logger.critical,
        }.get(severity, self.logger.info)

        log_method("[%s] [%s] %s", severity, alert_type, description)

        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                self.logger.debug("Alert callback error: %s", e)

    def _channel_hop_loop(self) -> None:
        channels = list(range(1, 14))
        idx = 0
        while self._hop_running:
            ch = channels[idx % len(channels)]
            try:
                if validate_interface(self.interface):
                    subprocess.run(
                        ["iwconfig", self.interface, "channel", str(ch)],
                        capture_output=True, text=True, timeout=5,
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            idx += 1
            time.sleep(self.hop_interval)

    def start(self) -> None:
        self._start_time = time.time()
        self.logger.info("Starting WIDS on %s", self.interface)
        self.logger.info("  Known APs: %d", len(self.known_aps))
        self.logger.info("  Channel hopping: %s", "Yes" if self.channel_hop else "No")
        self.logger.info("  Deauth threshold: %d frames / %ds",
                         self.deauth_threshold, self.deauth_window)
        self.logger.info("  Press Ctrl+C to stop\n")

        if self.channel_hop:
            self._hop_running = True
            hop_thread = threading.Thread(target=self._channel_hop_loop, daemon=True)
            hop_thread.start()

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
        except KeyboardInterrupt:
            pass
        finally:
            self._hop_running = False
            self.stop()

    def stop(self) -> None:
        self._stop_event.set()
        self._hop_running = False
        self.print_summary()
        self.save_alerts()

    def get_stats(self) -> dict:
        elapsed = time.time() - self._start_time if self._start_time else 0
        alert_counts: dict[str, int] = {}
        for alert in self.alerts:
            alert_counts[alert.alert_type] = alert_counts.get(alert.alert_type, 0) + 1

        return {
            "packets_processed": self._stats["packets_processed"],
            "alerts_total": len(self.alerts),
            "alerts_by_type": alert_counts,
            "unique_aps_seen": len(self._seen_aps),
            "uptime_seconds": round(elapsed, 1),
        }

    def get_alerts(self, severity: Optional[str] = None,
                   alert_type: Optional[str] = None,
                   limit: int = 100) -> list[Alert]:
        filtered = self.alerts
        if severity:
            filtered = [a for a in filtered if a.severity == severity]
        if alert_type:
            filtered = [a for a in filtered if a.alert_type == alert_type]
        return filtered[-limit:]

    def save_alerts(self) -> None:
        if not self.alerts:
            return

        try:
            os.makedirs(os.path.dirname(self.log_file) or ".", exist_ok=True)
            with open(self.log_file, "w", encoding="utf-8") as f:
                json.dump(
                    [dataclasses.asdict(a) for a in self.alerts],
                    f, indent=2,
                )
            self.logger.info("Alerts saved to %s", self.log_file)
        except Exception as e:
            self.logger.error("Failed to save alerts: %s", e)

    def print_summary(self) -> None:
        stats = self.get_stats()
        print(f"\n{'='*70}")
        print("WIDS Summary")
        print(f"{'='*70}")
        print(f"Packets processed:  {stats['packets_processed']}")
        print(f"Unique APs seen:    {stats['unique_aps_seen']}")
        print(f"Total alerts:       {stats['alerts_total']}")
        print(f"Uptime:             {stats['uptime_seconds']}s")

        if stats["alerts_by_type"]:
            print(f"\nAlerts by type:")
            for atype, count in sorted(stats["alerts_by_type"].items()):
                print(f"  {atype:<20} {count}")

        if self.alerts:
            print(f"\nRecent alerts:")
            for alert in self.alerts[-10:]:
                print(f"  [{alert.severity}] [{alert.alert_type}] {alert.description}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WIDS - Wireless Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start WIDS with channel hopping
  sudo python3 wids.py -i wlan0mon

  # With known AP list
  sudo python3 wids.py -i wlan0mon --known-aps known_aps.json

  # Custom deauth detection thresholds
  sudo python3 wids.py -i wlan0mon --deauth-threshold 5 --deauth-window 3

Known APs file format (JSON):
  {
    "AA:BB:CC:DD:EE:FF": {"ssid": "MyNetwork", "channel": 6},
    "11:22:33:44:55:66": {"ssid": "Office-WiFi", "channel": 1}
  }

Note: Interface must be in monitor mode.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("--known-aps",
                        help="JSON file with known AP list")
    parser.add_argument("--no-hop", action="store_true",
                        help="Disable channel hopping")
    parser.add_argument("--hop-interval", type=float, default=0.5,
                        help="Channel hop interval (default: 0.5)")
    parser.add_argument("--deauth-threshold", type=int, default=10,
                        help="Deauth frames threshold (default: 10)")
    parser.add_argument("--deauth-window", type=int, default=5,
                        help="Deauth detection window in seconds (default: 5)")
    parser.add_argument("-o", "--output", default="captures/wids_alerts.json",
                        help="Alert log file (default: captures/wids_alerts.json)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    if not check_monitor_mode(args.interface):
        logger = setup_logging("wids")
        logger.warning("%s may not be in monitor mode", args.interface)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)

    monitor = WIDSMonitor(
        interface=args.interface,
        known_aps_file=args.known_aps,
        channel_hop=not args.no_hop,
        hop_interval=args.hop_interval,
        deauth_threshold=args.deauth_threshold,
        deauth_window=args.deauth_window,
        log_file=args.output,
    )

    monitor.start()


if __name__ == "__main__":
    main()
