#!/usr/bin/env python3
"""
Packet Replay for Hoover WiFi Security Toolkit
Capture and replay WiFi frames for authorized security testing
"""

import argparse
import os
import sys
import threading
import time
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11ProbeReq
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sendp, sniff
from scapy.utils import rdpcap, wrpcap

from utils import check_monitor_mode, require_root, setup_logging, validate_mac

FILTER_TYPES = {
    "beacon": lambda p: p.haslayer(Dot11Beacon),
    "probe": lambda p: p.haslayer(Dot11ProbeReq),
    "deauth": lambda p: p.haslayer(Dot11Deauth),
    "eapol": lambda p: p.haslayer(EAPOL),
    "all": lambda p: True,
}


class PacketReplay:
    def __init__(self, interface: str, pcap_file: Optional[str] = None,
                 capture_timeout: int = 30, replay_count: int = 1,
                 replay_delay: float = 0.1, filter_type: Optional[str] = None,
                 filter_mac: Optional[str] = None) -> None:
        self.interface: str = interface
        self.pcap_file: Optional[str] = pcap_file
        self.capture_timeout: int = capture_timeout
        self.replay_count: int = replay_count
        self.replay_delay: float = replay_delay
        self.filter_type: Optional[str] = filter_type
        self.filter_mac: Optional[str] = filter_mac
        self.logger = setup_logging("packet_replay")
        self.captured_packets: list = []
        self.packets_sent: int = 0
        self._stop_event = threading.Event()
        self._stats: dict = {
            "packets_captured": 0,
            "packets_filtered": 0,
            "packets_replayed": 0,
            "capture_time": 0.0,
        }

    def capture(self) -> list:
        self.logger.info("Capturing packets on %s (timeout: %ds)", self.interface, self.capture_timeout)
        start = time.time()
        try:
            packets = sniff(
                iface=self.interface,
                timeout=self.capture_timeout,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
            self.captured_packets = list(packets)
            self._stats["packets_captured"] = len(self.captured_packets)
            self._stats["capture_time"] = round(time.time() - start, 2)
            self.logger.info("Captured %d packets in %.1fs",
                             len(self.captured_packets), self._stats["capture_time"])
            return self.captured_packets
        except KeyboardInterrupt:
            self.logger.info("Capture interrupted")
            return self.captured_packets

    def load_pcap(self, filepath: str) -> list:
        if not os.path.isfile(filepath):
            self.logger.error("File not found: %s", filepath)
            return []
        packets = list(rdpcap(filepath))
        self.captured_packets = packets
        self._stats["packets_captured"] = len(packets)
        self.logger.info("Loaded %d packets from %s", len(packets), filepath)
        return packets

    def save_pcap(self, packets: list, filepath: str) -> None:
        if not packets:
            self.logger.warning("No packets to save")
            return
        os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
        wrpcap(filepath, packets)
        self.logger.info("Saved %d packets to %s", len(packets), filepath)

    def filter_packets(self, packets: list) -> list:
        filtered = list(packets)

        if self.filter_type and self.filter_type in FILTER_TYPES:
            type_filter = FILTER_TYPES[self.filter_type]
            filtered = [p for p in filtered if type_filter(p)]

        if self.filter_mac:
            mac_upper = self.filter_mac.upper()
            def mac_match(pkt):
                if not pkt.haslayer(Dot11):
                    return False
                dot11 = pkt[Dot11]
                for i in range(1, 4):
                    addr = str(getattr(dot11, f"addr{i}", "") or "").upper()
                    if addr == mac_upper:
                        return True
                return False
            filtered = [p for p in filtered if mac_match(p)]

        self._stats["packets_filtered"] = len(filtered)
        self.logger.info("Filtered to %d packets", len(filtered))
        return filtered

    def replay(self, packets: list) -> int:
        if not packets:
            self.logger.warning("No packets to replay")
            return 0

        total_sent = 0
        self.logger.info("Replaying %d packets (count: %d, delay: %.2fs)",
                         len(packets), self.replay_count, self.replay_delay)

        for iteration in range(self.replay_count):
            if self._stop_event.is_set():
                break
            for pkt in packets:
                if self._stop_event.is_set():
                    break
                try:
                    sendp(pkt, iface=self.interface, verbose=False)
                    total_sent += 1
                except Exception as e:
                    self.logger.debug("Error replaying packet: %s", e)
                if self.replay_delay > 0:
                    time.sleep(self.replay_delay)

            self.logger.info("Replay iteration %d/%d complete (%d packets sent)",
                             iteration + 1, self.replay_count, total_sent)

        self.packets_sent = total_sent
        self._stats["packets_replayed"] = total_sent
        return total_sent

    def get_stats(self) -> dict:
        return dict(self._stats)

    def start(self) -> None:
        if self.pcap_file:
            packets = self.load_pcap(self.pcap_file)
        else:
            packets = self.capture()

        if self.filter_type or self.filter_mac:
            packets = self.filter_packets(packets)

        if packets:
            self.replay(packets)

        self.print_summary()

    def stop(self) -> None:
        self._stop_event.set()

    def print_summary(self) -> None:
        stats = self.get_stats()
        print(f"\n{'='*60}")
        print("Packet Replay Summary")
        print(f"{'='*60}")
        print(f"Packets captured/loaded: {stats['packets_captured']}")
        print(f"Packets after filter:    {stats['packets_filtered']}")
        print(f"Packets replayed:        {stats['packets_replayed']}")
        if stats["capture_time"]:
            print(f"Capture time:            {stats['capture_time']}s")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Packet Replay - Capture and replay WiFi frames",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture and replay packets
  sudo python3 packet_replay.py -i wlan0mon -t 30 -c 3

  # Replay from pcap file
  sudo python3 packet_replay.py -i wlan0mon -r capture.pcap -c 5

  # Capture only beacons and save
  sudo python3 packet_replay.py -i wlan0mon -t 60 --filter beacon -w beacons.pcap

  # Replay deauth frames targeting specific MAC
  sudo python3 packet_replay.py -i wlan0mon -r capture.pcap --filter deauth --filter-mac AA:BB:CC:DD:EE:FF

Note: Interface must be in monitor mode.
      For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-r", "--read",
                        help="PCAP file to replay")
    parser.add_argument("-w", "--write",
                        help="Save captured packets to PCAP file")
    parser.add_argument("-c", "--count", type=int, default=1,
                        help="Number of replay iterations (default: 1)")
    parser.add_argument("-d", "--delay", type=float, default=0.1,
                        help="Delay between packets in seconds (default: 0.1)")
    parser.add_argument("--filter", choices=list(FILTER_TYPES.keys()),
                        help="Filter packets by type")
    parser.add_argument("--filter-mac",
                        help="Filter packets by MAC address")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                        help="Capture timeout in seconds (default: 30)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    if args.filter_mac:
        ok, err = validate_mac(args.filter_mac)
        if not ok:
            logger = setup_logging("packet_replay")
            logger.error("Invalid MAC format: %s", args.filter_mac)
            sys.exit(1)

    if not check_monitor_mode(args.interface):
        logger = setup_logging("packet_replay")
        logger.warning("%s may not be in monitor mode", args.interface)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)

    replayer = PacketReplay(
        interface=args.interface,
        pcap_file=args.read,
        capture_timeout=args.timeout,
        replay_count=args.count,
        replay_delay=args.delay,
        filter_type=args.filter,
        filter_mac=args.filter_mac,
    )

    if args.read:
        packets = replayer.load_pcap(args.read)
    else:
        packets = replayer.capture()

    if args.filter or args.filter_mac:
        packets = replayer.filter_packets(packets)

    if args.write:
        replayer.save_pcap(packets, args.write)

    if packets and not args.write:
        replayer.replay(packets)

    replayer.print_summary()


if __name__ == "__main__":
    main()
