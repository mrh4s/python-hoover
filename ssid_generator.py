#!/usr/bin/env python3
"""
SSID Generator Add-on for Hoover
Broadcasts SSIDs from a text file on a specified wireless interface
Used for testing, research, and authorized penetration testing
"""

import argparse
import subprocess
import sys
import time
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.sendrecv import sendp

from utils import (
    check_monitor_mode,
    load_ssids,
    require_root,
    setup_logging,
    validate_interface,
)


class SSIDGenerator:
    def __init__(
        self, interface: Optional[str], ssid_file: str, interval: float = 0.1, channel: int = 6
    ) -> None:
        self.interface: Optional[str] = interface
        self.ssid_file: str = ssid_file
        self.interval: float = interval
        self.channel: int = channel
        self.ssids: list[str] = []
        self.logger = setup_logging("ssid_generator")

    def load_ssids_from_file(self) -> bool:
        """Load SSIDs from text file."""
        try:
            self.ssids = load_ssids(self.ssid_file)

            if not self.ssids:
                self.logger.error("No SSIDs found in file")
                sys.exit(1)

            self.logger.info("Loaded %d SSIDs from %s", len(self.ssids), self.ssid_file)
            return True

        except FileNotFoundError:
            self.logger.error("File '%s' not found", self.ssid_file)
            sys.exit(1)
        except Exception as e:
            self.logger.error("Error loading SSIDs: %s", e)
            sys.exit(1)

    def generate_mac(self, index: int) -> str:
        """Generate unique MAC address for each SSID."""
        # Create unique locally administered MAC
        mac_bytes = [0x02, 0x00, 0x00, (index >> 16) & 0xFF, (index >> 8) & 0xFF, index & 0xFF]
        return ":".join(f"{b:02x}" for b in mac_bytes)

    def create_beacon(self, ssid: str, bssid: str) -> object:
        """Create a WiFi beacon frame."""
        # RadioTap header
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)

        # Beacon frame
        beacon = Dot11Beacon(cap="ESS+privacy")

        # Information elements
        essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))

        # Supported rates
        rates = Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")

        # DS Parameter set (channel)
        dsset = Dot11Elt(ID="DSset", info=chr(self.channel).encode())

        # Construct full frame
        frame = RadioTap() / dot11 / beacon / essid / rates / dsset

        return frame

    def set_channel(self) -> None:
        """Set the wireless interface to the specified channel."""
        try:
            if not self.interface or not validate_interface(self.interface):
                raise ValueError(f"Invalid interface name: {self.interface}")

            if not isinstance(self.channel, int) or self.channel < 1 or self.channel > 14:
                raise ValueError(f"Invalid channel: {self.channel}")

            result = subprocess.run(
                ["iwconfig", self.interface, "channel", str(self.channel)],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                self.logger.info("Set %s to channel %d", self.interface, self.channel)
            else:
                self.logger.warning("Could not set channel: %s", result.stderr)
        except subprocess.TimeoutExpired:
            self.logger.warning("Timeout setting channel")
        except ValueError as e:
            self.logger.error("Error: %s", e)
        except Exception as e:
            self.logger.warning("Could not set channel: %s", e)

    def start_broadcast(self, continuous: bool = False) -> None:
        """Start broadcasting SSIDs."""
        self.logger.info("Starting SSID broadcast on %s", self.interface)
        self.logger.info("Broadcasting %d SSIDs", len(self.ssids))
        self.logger.info("Interval: %ss between frames", self.interval)
        self.logger.info("Channel: %d", self.channel)
        self.logger.info("Mode: %s", "Continuous" if continuous else "Single pass")
        self.logger.info("Press Ctrl+C to stop\n")

        # Set channel
        self.set_channel()

        try:
            iteration: int = 0
            while True:
                iteration += 1
                self.logger.info("Broadcasting iteration %d...", iteration)

                for idx, ssid in enumerate(self.ssids):
                    # Generate unique MAC for this SSID
                    bssid: str = self.generate_mac(idx)

                    # Create and send beacon
                    frame = self.create_beacon(ssid, bssid)

                    try:
                        sendp(frame, iface=self.interface, verbose=False)
                        self.logger.info(
                            "  [%d/%d] Broadcasting: %s (%s)",
                            idx + 1,
                            len(self.ssids),
                            ssid[:32],
                            bssid,
                        )
                        time.sleep(self.interval)

                    except Exception as e:
                        self.logger.error("Error broadcasting %s: %s", ssid, e)

                if not continuous:
                    self.logger.info("Single pass completed")
                    break

                time.sleep(0.5)  # Brief pause between iterations

        except KeyboardInterrupt:
            self.logger.info("\nBroadcast stopped by user")
        except Exception as e:
            self.logger.error("Error during broadcast: %s", e)
            sys.exit(1)

    def list_ssids(self) -> None:
        """List all SSIDs from the file."""
        print(f"\nSSIDs in {self.ssid_file}:")
        print("-" * 50)
        for idx, ssid in enumerate(self.ssids, 1):
            print(f"{idx:3d}. {ssid}")
        print(f"\nTotal: {len(self.ssids)} SSIDs")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SSID Generator - Broadcast SSIDs from a text file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Broadcast SSIDs once from file
  sudo python3 ssid_generator.py -i wlan0mon -f ssids.txt

  # Continuously broadcast SSIDs
  sudo python3 ssid_generator.py -i wlan0mon -f ssids.txt -c

  # Custom interval and channel
  sudo python3 ssid_generator.py -i wlan0mon -f ssids.txt -t 0.5 -ch 11

  # List SSIDs in file
  python3 ssid_generator.py -f ssids.txt -l

File Format:
  - One SSID per line
  - Lines starting with # are comments
  - Empty lines are ignored
  - Example:
    # Corporate networks
    CoffeeShop-WiFi
    Hotel-Guest
    Airport-Free-WiFi

Note: Interface must be in monitor mode for broadcasting
      """,
    )

    parser.add_argument("-i", "--interface", help="Wireless interface in monitor mode")
    parser.add_argument(
        "-f", "--file", required=True, help="Text file containing SSIDs (one per line)"
    )
    parser.add_argument(
        "-c", "--continuous", action="store_true", help="Continuously broadcast SSIDs (loop)"
    )
    parser.add_argument(
        "-t",
        "--interval",
        type=float,
        default=0.1,
        help="Time interval between frames in seconds (default: 0.1)",
    )
    parser.add_argument(
        "-ch", "--channel", type=int, default=6, help="WiFi channel to use (default: 6)"
    )
    parser.add_argument(
        "-l", "--list", action="store_true", help="List SSIDs from file and exit (no root required)"
    )

    args = parser.parse_args()

    logger = setup_logging("ssid_generator")

    # Create generator instance
    generator = SSIDGenerator(args.interface, args.file, args.interval, args.channel)

    # Load SSIDs
    generator.load_ssids_from_file()

    # If just listing, don't require root or interface
    if args.list:
        generator.list_ssids()
        sys.exit(0)

    # For broadcasting, check requirements
    if not args.interface:
        logger.error("Interface (-i) is required for broadcasting")
        logger.error("Use -l to just list SSIDs without broadcasting")
        sys.exit(1)

    # Check if running as root
    require_root()

    # Check if interface is in monitor mode
    if not check_monitor_mode(args.interface):
        logger.warning("%s may not be in monitor mode", args.interface)
        logger.warning("Enable monitor mode with: sudo airmon-ng start <interface>")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)

    # Start broadcasting
    generator.start_broadcast(args.continuous)


if __name__ == "__main__":
    main()
