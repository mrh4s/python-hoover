#!/usr/bin/env python3
"""
Hoover - WiFi Probe Request Monitor
Captures and analyzes probe requests from nearby wireless devices
"""

import sys
import argparse
from scapy.all import *
from datetime import datetime
from collections import defaultdict

class ProbeMonitor:
    def __init__(self, interface, verbose=False):
        self.interface = interface
        self.verbose = verbose
        self.probes = defaultdict(set)

    def packet_handler(self, packet):
        """Handle captured WiFi packets"""
        if packet.haslayer(Dot11ProbeReq):
            try:
                # Extract client MAC address
                client_mac = packet[Dot11].addr2

                # Extract SSID from probe request
                ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')

                # Skip empty SSIDs (broadcast probes)
                if ssid:
                    # Track new probes
                    if ssid not in self.probes[client_mac]:
                        self.probes[client_mac].add(ssid)
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"[{timestamp}] {client_mac} -> {ssid}")

                        if self.verbose:
                            print(f"  Signal Strength: {packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else 'N/A'} dBm")

            except Exception as e:
                if self.verbose:
                    print(f"Error parsing packet: {e}")

    def start(self):
        """Start monitoring probe requests"""
        print(f"[*] Starting Hoover on interface {self.interface}")
        print("[*] Monitoring probe requests... (Press Ctrl+C to stop)\n")
        print(f"{'Time':<10} {'Client MAC':<20} {'SSID'}")
        print("-" * 60)

        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\n\n[*] Monitoring stopped")
            self.print_summary()
        except Exception as e:
            print(f"[!] Error: {e}")
            print("[!] Make sure the interface is in monitor mode")
            sys.exit(1)

    def print_summary(self):
        """Print summary of captured probes"""
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total clients detected: {len(self.probes)}")
        print(f"\nProbe requests by client:")

        for client, ssids in self.probes.items():
            print(f"\n{client}:")
            for ssid in sorted(ssids):
                print(f"  - {ssid}")

def main():
    parser = argparse.ArgumentParser(
        description="Hoover - WiFi Probe Request Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 hoover.py -i wlan0mon
  sudo python3 hoover.py -i wlan0mon -v

Note: Interface must be in monitor mode
        """
    )

    parser.add_argument('-i', '--interface', required=True,
                       help='Wireless interface in monitor mode')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')

    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script must be run as root (use sudo)")
        sys.exit(1)

    # Start monitoring
    monitor = ProbeMonitor(args.interface, args.verbose)
    monitor.start()

if __name__ == "__main__":
    main()
