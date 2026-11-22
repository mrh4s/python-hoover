#!/usr/bin/env python3
"""
AP Scanner for Hoover WiFi Security Toolkit
Passively scans for nearby WiFi access points by sniffing beacon and probe response frames
"""

import sys
import os
import argparse
import csv
import json
import threading
import subprocess
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap
from scapy.sendrecv import sniff

from utils import validate_interface, check_monitor_mode, require_root, setup_logging, get_channels
from oui_lookup import lookup_vendor


class APScanner:
    def __init__(self, interface: str, timeout: int = 30,
                 channel_hop: bool = True, hop_interval: float = 0.5,
                 fixed_channel: Optional[int] = None,
                 output_file: Optional[str] = None,
                 bands: str = "2.4") -> None:
        self.interface: str = interface
        self.timeout: int = timeout
        self.channel_hop: bool = channel_hop
        self.hop_interval: float = hop_interval
        self.fixed_channel: Optional[int] = fixed_channel
        self.output_file: Optional[str] = output_file
        self.bands: str = bands
        self.logger = setup_logging("ap_scanner")
        self.access_points: dict[str, dict] = {}
        self._hop_running: bool = False

    def packet_handler(self, packet) -> None:
        if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
            return

        try:
            bssid = packet[Dot11].addr3
            if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                return
            bssid = bssid.upper()

            ssid = ""
            channel = None
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace")
                    except Exception:
                        ssid = ""
                elif elt.ID == 3 and elt.info:
                    channel = elt.info[0]
                elt = elt.payload.getlayer(Dot11Elt)

            signal = None
            if packet.haslayer(RadioTap):
                try:
                    signal = packet[RadioTap].dBm_AntSignal
                except Exception:
                    pass

            self._last_akm_suites = []
            encryption = self._determine_encryption(packet)
            akm_suites = list(self._last_akm_suites)
            vendor = lookup_vendor(bssid)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if bssid in self.access_points:
                ap = self.access_points[bssid]
                ap["beacon_count"] += 1
                ap["last_seen"] = now
                if signal is not None and (ap["signal"] is None or signal > ap["signal"]):
                    ap["signal"] = signal
                if ssid and not ap["ssid"]:
                    ap["ssid"] = ssid
                if channel and not ap["channel"]:
                    ap["channel"] = channel
            else:
                self.access_points[bssid] = {
                    "ssid": ssid,
                    "channel": channel,
                    "signal": signal,
                    "encryption": encryption,
                    "akm_suites": akm_suites,
                    "vendor": vendor,
                    "first_seen": now,
                    "last_seen": now,
                    "beacon_count": 1,
                }
                self.logger.info(
                    "New AP: %s  SSID: %-32s  CH: %-3s  Enc: %-9s  Signal: %s  Vendor: %s",
                    bssid, ssid or "<hidden>", channel or "?", encryption,
                    f"{signal}dBm" if signal is not None else "?", vendor,
                )

        except Exception as e:
            self.logger.debug("Error processing packet: %s", e)

    def _determine_encryption(self, packet) -> str:
        if not packet.haslayer(Dot11Beacon) and not packet.haslayer(Dot11ProbeResp):
            return "Unknown"

        layer = packet[Dot11Beacon] if packet.haslayer(Dot11Beacon) else packet[Dot11ProbeResp]
        cap = layer.cap if hasattr(layer, "cap") else 0

        has_privacy = bool(cap & 0x0010) if isinstance(cap, int) else "privacy" in str(cap)

        if not has_privacy:
            return "Open"

        elt = packet.getlayer(Dot11Elt)
        has_rsn = False
        has_wpa = False
        rsn_info = b""
        while elt:
            if elt.ID == 48:
                has_rsn = True
                rsn_info = bytes(elt.info or b"")
            if elt.ID == 221 and elt.info and len(elt.info) >= 4:
                oui = elt.info[:3]
                if oui == b"\x00\x50\xf2" and elt.info[3:4] == b"\x01":
                    has_wpa = True
            elt = elt.payload.getlayer(Dot11Elt)

        if has_rsn:
            parsed = self._parse_rsn_ie(rsn_info)
            self._last_akm_suites = parsed["akm_suites"]
            return self._encryption_from_akms(parsed["akm_suites"])
        if has_wpa:
            return "WPA"
        return "WEP"

    @staticmethod
    def _encryption_from_akms(akms: list) -> str:
        """Map a list of AKM suite names to an encryption label."""
        akm_set = set(akms)
        has_sae = bool(akm_set & {"SAE", "FT-SAE", "SAE-EXT", "FT-SAE-EXT"})
        has_psk = bool(akm_set & {"PSK", "FT-PSK", "PSK-SHA256"})
        has_8021x = bool(akm_set & {"802.1X", "FT-802.1X", "802.1X-SHA256"})
        has_192 = "802.1X-SUITE-B-192" in akm_set or "802.1X-SUITE-B" in akm_set
        if has_sae and has_psk:
            return "WPA3/WPA2"
        if has_sae:
            return "WPA3"
        if has_192:
            return "WPA3-Enterprise"
        if has_8021x:
            return "WPA2-Enterprise"
        if "OWE" in akm_set:
            return "OWE"
        # PSK, or RSN IE that is truncated/unknown: keep legacy behaviour
        return "WPA2"

    def _parse_rsn_ie(self, rsn_data: bytes) -> dict:
        """Parse an RSN IE body (after tag and length bytes)."""
        result = {"akm_suites": [], "pairwise_ciphers": [], "group_cipher": ""}
        cipher_names = {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104",
                        8: "GCMP", 9: "GCMP-256", 10: "CCMP-256"}
        akm_names = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK",
                     5: "802.1X-SHA256", 6: "PSK-SHA256", 8: "SAE",
                     9: "FT-SAE", 11: "802.1X-SUITE-B", 12: "SAE-EXT",
                     13: "FT-SAE-EXT", 18: "OWE", 24: "SAE-EXT",
                     25: "FT-SAE-EXT"}
        oui = b"\x00\x0f\xac"
        try:
            data = bytes(rsn_data or b"")
            pos = 2  # version
            if len(data) < pos + 4:
                return result
            if data[pos:pos + 3] == oui:
                result["group_cipher"] = cipher_names.get(data[pos + 3], f"Unknown({data[pos + 3]})")
            pos += 4
            if len(data) < pos + 2:
                return result
            count = int.from_bytes(data[pos:pos + 2], "little")
            pos += 2
            for _ in range(count):
                if len(data) < pos + 4:
                    return result
                if data[pos:pos + 3] == oui:
                    result["pairwise_ciphers"].append(
                        cipher_names.get(data[pos + 3], f"Unknown({data[pos + 3]})"))
                pos += 4
            if len(data) < pos + 2:
                return result
            count = int.from_bytes(data[pos:pos + 2], "little")
            pos += 2
            for _ in range(count):
                if len(data) < pos + 4:
                    return result
                if data[pos:pos + 3] == oui:
                    result["akm_suites"].append(
                        akm_names.get(data[pos + 3], f"Unknown({data[pos + 3]})"))
                pos += 4
        except Exception:
            pass
        return result

    def _channel_hop_loop(self) -> None:
        channels = get_channels(self.bands)
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

    def _set_channel(self, channel: int) -> None:
        try:
            if validate_interface(self.interface):
                subprocess.run(
                    ["iwconfig", self.interface, "channel", str(channel)],
                    capture_output=True, text=True, timeout=5,
                )
                self.logger.info("Set channel to %d", channel)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            self.logger.warning("Could not set channel: %s", e)

    def start(self) -> dict[str, dict]:
        self.logger.info("Starting AP scan on %s (timeout: %ds)", self.interface, self.timeout)

        if self.fixed_channel:
            self._set_channel(self.fixed_channel)
        elif self.channel_hop:
            self._hop_running = True
            hop_thread = threading.Thread(target=self._channel_hop_loop, daemon=True)
            hop_thread.start()

        try:
            sniff(iface=self.interface, prn=self.packet_handler,
                  timeout=self.timeout, store=0)
        except KeyboardInterrupt:
            self.logger.info("Scan interrupted by user")
        finally:
            self._hop_running = False

        return self.access_points

    def save_results(self) -> None:
        if not self.output_file or not self.access_points:
            return

        ext = os.path.splitext(self.output_file)[1].lower()
        os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)

        if ext == ".csv":
            with open(self.output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["bssid", "ssid", "channel", "signal", "encryption",
                                 "vendor", "beacon_count", "first_seen", "last_seen"])
                for bssid, ap in self.access_points.items():
                    writer.writerow([
                        bssid, ap["ssid"], ap["channel"], ap["signal"],
                        ap["encryption"], ap["vendor"], ap["beacon_count"],
                        ap["first_seen"], ap["last_seen"],
                    ])
            self.logger.info("Results saved to %s", self.output_file)

        elif ext == ".json":
            with open(self.output_file, "w", encoding="utf-8") as f:
                json.dump(self.access_points, f, indent=2)
            self.logger.info("Results saved to %s", self.output_file)

    def print_results(self) -> None:
        if not self.access_points:
            self.logger.info("No access points found")
            return

        print(f"\n{'='*104}")
        print(f"{'BSSID':<20} {'SSID':<25} {'CH':<5} {'Signal':<8} {'Enc':<10} {'Vendor':<20} {'Beacons':<8}")
        print(f"{'='*104}")
        for bssid, ap in sorted(self.access_points.items(),
                                 key=lambda x: x[1].get("signal") or -100, reverse=True):
            sig_str = f"{ap['signal']}dBm" if ap["signal"] is not None else "?"
            print(f"{bssid:<20} {(ap['ssid'] or '<hidden>'):<25} "
                  f"{str(ap['channel'] or '?'):<5} {sig_str:<8} "
                  f"{ap['encryption']:<10} {ap['vendor'][:20]:<20} {ap['beacon_count']:<8}")
        print(f"\nTotal: {len(self.access_points)} access points found")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AP Scanner - Discover nearby WiFi access points",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan for 60 seconds with channel hopping
  sudo python3 ap_scanner.py -i wlan0mon -t 60

  # Scan fixed channel 6
  sudo python3 ap_scanner.py -i wlan0mon -ch 6

  # Save results to CSV
  sudo python3 ap_scanner.py -i wlan0mon -o scan_results.csv

Note: Interface must be in monitor mode
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                        help="Scan duration in seconds (default: 30)")
    parser.add_argument("--no-hop", action="store_true",
                        help="Disable channel hopping")
    parser.add_argument("-ch", "--channel", type=int,
                        help="Fixed channel to scan")
    parser.add_argument("--hop-interval", type=float, default=0.5,
                        help="Channel hop interval in seconds (default: 0.5)")
    parser.add_argument("--bands", default="2.4,5",
                        choices=["2.4", "5", "2.4,5", "all"],
                        help="Frequency bands to scan: 2.4, 5, 2.4,5, all (default: 2.4,5)")
    parser.add_argument("-o", "--output",
                        help="Output file path (.csv or .json)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    if not check_monitor_mode(args.interface):
        logger = setup_logging("ap_scanner")
        logger.warning("%s may not be in monitor mode", args.interface)
        logger.warning("Enable with: sudo airmon-ng start <interface>")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)

    scanner = APScanner(
        interface=args.interface,
        timeout=args.timeout,
        channel_hop=not args.no_hop,
        hop_interval=args.hop_interval,
        fixed_channel=args.channel,
        output_file=args.output,
        bands=args.bands,
    )

    scanner.start()
    scanner.print_results()
    scanner.save_results()


if __name__ == "__main__":
    main()
