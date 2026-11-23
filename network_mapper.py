#!/usr/bin/env python3
"""
Network Mapper for Hoover WiFi Security Toolkit
Network discovery via ARP scanning and port probing
For authorized security testing and research only
"""

import argparse
import csv
import json
import os
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

from oui_lookup import lookup_vendor
from utils import require_root, setup_logging

DEFAULT_PORTS: list[int] = [
    22, 23, 53, 80, 110, 143, 443, 445,
    993, 995, 3306, 3389, 5432, 8080, 8443,
]


class NetworkMapper:
    def __init__(self, interface: str, target_range: str = "192.168.1.0/24",
                 port_scan: bool = True,
                 common_ports: Optional[list[int]] = None,
                 timeout: float = 2.0,
                 output_file: Optional[str] = None) -> None:
        self.interface: str = interface
        self.target_range: str = target_range
        self.port_scan: bool = port_scan
        self.common_ports: list[int] = common_ports if common_ports is not None else list(DEFAULT_PORTS)
        self.timeout: float = timeout
        self.output_file: Optional[str] = output_file
        self.logger = setup_logging("network_mapper")
        self._stop_event = threading.Event()
        self._stats: dict = {
            "hosts_found": 0,
            "open_ports_found": 0,
            "scan_time": 0.0,
        }

    def arp_scan(self) -> list[dict]:
        self.logger.info("ARP scanning %s on %s...", self.target_range, self.interface)

        try:
            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target_range)
            answered, _ = srp(arp_request, iface=self.interface, timeout=self.timeout, verbose=False)

            hosts = []
            for _sent, received in answered:
                mac = received.hwsrc.upper()
                vendor = lookup_vendor(mac)
                hosts.append({
                    "ip": received.psrc,
                    "mac": mac,
                    "vendor": vendor,
                })

            self._stats["hosts_found"] = len(hosts)
            self.logger.info("Found %d hosts", len(hosts))
            return hosts

        except Exception as e:
            self.logger.error("ARP scan failed: %s", e)
            return []

    def _scan_port(self, ip: str, port: int) -> Optional[dict]:
        if self._stop_event.is_set():
            return None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = self._grab_banner(sock)
                sock.close()
                return {"port": port, "state": "open", "banner": banner}
            sock.close()
        except (socket.timeout, OSError):
            pass
        return None

    def _grab_banner(self, sock: socket.socket) -> str:
        try:
            sock.settimeout(1.0)
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner[:200]
        except (socket.timeout, OSError, UnicodeDecodeError):
            return ""

    def port_scan_host(self, target_ip: str) -> list[dict]:
        if not self.port_scan or not self.common_ports:
            return []

        self.logger.info("Port scanning %s (%d ports)...", target_ip, len(self.common_ports))
        open_ports = []

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._scan_port, target_ip, port): port
                for port in self.common_ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    self._stats["open_ports_found"] += 1

        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    def scan_network(self) -> dict:
        start_time = time.time()
        self.logger.info("Starting network scan of %s", self.target_range)

        hosts = self.arp_scan()

        if self.port_scan:
            for host in hosts:
                if self._stop_event.is_set():
                    break
                host["ports"] = self.port_scan_host(host["ip"])
        else:
            for host in hosts:
                host["ports"] = []

        scan_time = round(time.time() - start_time, 2)
        self._stats["scan_time"] = scan_time

        results = {
            "target_range": self.target_range,
            "interface": self.interface,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_time": scan_time,
            "host_count": len(hosts),
            "hosts": hosts,
        }

        self.logger.info("Scan complete: %d hosts, %d open ports in %.1fs",
                         len(hosts), self._stats["open_ports_found"], scan_time)
        return results

    def save_results(self, results: dict) -> None:
        if not self.output_file:
            return

        os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)
        ext = os.path.splitext(self.output_file)[1].lower()

        if ext == ".json":
            with open(self.output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
        elif ext == ".csv":
            with open(self.output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "mac", "vendor", "open_ports", "banners"])
                for host in results.get("hosts", []):
                    ports_str = ",".join(str(p["port"]) for p in host.get("ports", []))
                    banners_str = "; ".join(
                        f"{p['port']}:{p['banner']}" for p in host.get("ports", []) if p.get("banner")
                    )
                    writer.writerow([host["ip"], host["mac"], host["vendor"], ports_str, banners_str])
        else:
            with open(self.output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)

        self.logger.info("Results saved to %s", self.output_file)

    def print_results(self, results: dict) -> None:
        hosts = results.get("hosts", [])
        if not hosts:
            self.logger.info("No hosts found")
            return

        print(f"\n{'='*80}")
        print(f"Network Map: {results.get('target_range', '?')}")
        print(f"{'='*80}")

        for host in hosts:
            print(f"\n  {host['ip']:<16} {host['mac']:<20} {host['vendor']}")
            for port in host.get("ports", []):
                banner_str = f" ({port['banner']})" if port.get("banner") else ""
                print(f"    Port {port['port']:<6} {port['state']}{banner_str}")

        print(f"\n{'='*80}")
        print(f"Total: {len(hosts)} hosts, {self._stats['open_ports_found']} open ports")
        print(f"Scan time: {results.get('scan_time', 0)}s")

    def get_stats(self) -> dict:
        return dict(self._stats)

    def stop(self) -> None:
        self._stop_event.set()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Mapper - ARP scan and port discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan default range
  sudo python3 network_mapper.py -i wlan0

  # Scan specific range with port scan
  sudo python3 network_mapper.py -i eth0 -r 10.0.0.0/24

  # ARP scan only (no port scan)
  sudo python3 network_mapper.py -i wlan0 -r 192.168.1.0/24 --no-port-scan

  # Custom ports, save to JSON
  sudo python3 network_mapper.py -i eth0 -p 22,80,443,8080 -o scan.json

Note: For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Network interface")
    parser.add_argument("-r", "--range", default="192.168.1.0/24",
                        help="Target IP range in CIDR (default: 192.168.1.0/24)")
    parser.add_argument("--no-port-scan", action="store_true",
                        help="Skip port scanning")
    parser.add_argument("-p", "--ports",
                        help="Comma-separated list of ports to scan")
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                        help="Timeout in seconds (default: 2.0)")
    parser.add_argument("-o", "--output",
                        help="Output file (.json or .csv)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            logger = setup_logging("network_mapper")
            logger.error("Invalid port list: %s", args.ports)
            sys.exit(1)

    mapper = NetworkMapper(
        interface=args.interface,
        target_range=args.range,
        port_scan=not args.no_port_scan,
        common_ports=ports,
        timeout=args.timeout,
        output_file=args.output,
    )

    results = mapper.scan_network()
    mapper.print_results(results)
    mapper.save_results(results)


if __name__ == "__main__":
    main()
