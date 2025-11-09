#!/usr/bin/env python3
"""
SSID Generator Add-on for Hoover
Broadcasts SSIDs from a text file on a specified wireless interface
Used for testing, research, and authorized penetration testing
"""

import sys
import os
import argparse
import time
import subprocess
import shlex
from scapy.all import *

class SSIDGenerator:
    def __init__(self, interface, ssid_file, interval=0.1, channel=6):
        self.interface = interface
        self.ssid_file = ssid_file
        self.interval = interval
        self.channel = channel
        self.ssids = []
        self.mac_base = "02:00:00:00:00:00"  # Locally administered MAC address

    def load_ssids(self):
        """Load SSIDs from text file"""
        try:
            with open(self.ssid_file, 'r', encoding='utf-8') as f:
                self.ssids = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            if not self.ssids:
                print("[!] No SSIDs found in file")
                sys.exit(1)

            print(f"[+] Loaded {len(self.ssids)} SSIDs from {self.ssid_file}")
            return True

        except FileNotFoundError:
            print(f"[!] Error: File '{self.ssid_file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error loading SSIDs: {e}")
            sys.exit(1)

    def generate_mac(self, index):
        """Generate unique MAC address for each SSID"""
        # Create unique locally administered MAC
        mac_bytes = [0x02, 0x00, 0x00,
                     (index >> 16) & 0xFF,
                     (index >> 8) & 0xFF,
                     index & 0xFF]
        return ':'.join(f'{b:02x}' for b in mac_bytes)

    def create_beacon(self, ssid, bssid):
        """Create a WiFi beacon frame"""
        # RadioTap header
        dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                     addr2=bssid, addr3=bssid)

        # Beacon frame
        beacon = Dot11Beacon(cap='ESS+privacy')

        # Information elements
        essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))

        # Supported rates
        rates = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')

        # DS Parameter set (channel)
        dsset = Dot11Elt(ID='DSset', info=chr(self.channel).encode())

        # Construct full frame
        frame = RadioTap()/dot11/beacon/essid/rates/dsset

        return frame

    def set_channel(self):
        """Set the wireless interface to the specified channel"""
        try:
            # Validate interface name to prevent command injection
            if not self.interface.replace('-', '').replace('_', '').isalnum():
                raise ValueError(f"Invalid interface name: {self.interface}")

            # Validate channel number
            if not isinstance(self.channel, int) or self.channel < 1 or self.channel > 14:
                raise ValueError(f"Invalid channel: {self.channel}")

            # Use subprocess.run instead of os.system to prevent command injection
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

    def start_broadcast(self, continuous=False):
        """Start broadcasting SSIDs"""
        print(f"[*] Starting SSID broadcast on {self.interface}")
        print(f"[*] Broadcasting {len(self.ssids)} SSIDs")
        print(f"[*] Interval: {self.interval}s between frames")
        print(f"[*] Channel: {self.channel}")
        print(f"[*] Mode: {'Continuous' if continuous else 'Single pass'}")
        print("[*] Press Ctrl+C to stop\n")

        # Set channel
        self.set_channel()

        try:
            iteration = 0
            while True:
                iteration += 1
                print(f"\n[+] Broadcasting iteration {iteration}...")

                for idx, ssid in enumerate(self.ssids):
                    # Generate unique MAC for this SSID
                    bssid = self.generate_mac(idx)

                    # Create and send beacon
                    frame = self.create_beacon(ssid, bssid)

                    try:
                        sendp(frame, iface=self.interface, verbose=False)
                        print(f"  [{idx+1}/{len(self.ssids)}] Broadcasting: {ssid[:32]} ({bssid})")
                        time.sleep(self.interval)

                    except Exception as e:
                        print(f"  [!] Error broadcasting {ssid}: {e}")

                if not continuous:
                    print("\n[+] Single pass completed")
                    break

                time.sleep(0.5)  # Brief pause between iterations

        except KeyboardInterrupt:
            print("\n\n[*] Broadcast stopped by user")
        except Exception as e:
            print(f"\n[!] Error during broadcast: {e}")
            sys.exit(1)

    def list_ssids(self):
        """List all SSIDs from the file"""
        print(f"\nSSIDs in {self.ssid_file}:")
        print("-" * 50)
        for idx, ssid in enumerate(self.ssids, 1):
            print(f"{idx:3d}. {ssid}")
        print(f"\nTotal: {len(self.ssids)} SSIDs")

def check_monitor_mode(interface):
    """Check if interface is in monitor mode"""
    try:
        # Validate interface name to prevent command injection
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
      """
    )

    parser.add_argument('-i', '--interface',
                       help='Wireless interface in monitor mode')
    parser.add_argument('-f', '--file', required=True,
                       help='Text file containing SSIDs (one per line)')
    parser.add_argument('-c', '--continuous', action='store_true',
                       help='Continuously broadcast SSIDs (loop)')
    parser.add_argument('-t', '--interval', type=float, default=0.1,
                       help='Time interval between frames in seconds (default: 0.1)')
    parser.add_argument('-ch', '--channel', type=int, default=6,
                       help='WiFi channel to use (default: 6)')
    parser.add_argument('-l', '--list', action='store_true',
                       help='List SSIDs from file and exit (no root required)')

    args = parser.parse_args()

    # Create generator instance
    generator = SSIDGenerator(args.interface, args.file, args.interval, args.channel)

    # Load SSIDs
    generator.load_ssids()

    # If just listing, don't require root or interface
    if args.list:
        generator.list_ssids()
        sys.exit(0)

    # For broadcasting, check requirements
    if not args.interface:
        print("[!] Error: Interface (-i) is required for broadcasting")
        print("    Use -l to just list SSIDs without broadcasting")
        sys.exit(1)

    # Check if running as root
    if os.geteuid() != 0:
        print("[!] Broadcasting requires root privileges (use sudo)")
        sys.exit(1)

    # Check if interface is in monitor mode
    if not check_monitor_mode(args.interface):
        print(f"[!] Warning: {args.interface} may not be in monitor mode")
        print("[!] Enable monitor mode with: sudo airmon-ng start <interface>")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)

    # Start broadcasting
    generator.start_broadcast(args.continuous)

if __name__ == "__main__":
    main()
