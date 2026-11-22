#!/usr/bin/env python3
"""
802.11r Fast BSS Transition (FT) Vulnerability Detection Module
for Hoover WiFi Security Toolkit.

Detects 802.11r (Fast BSS Transition) implementations vulnerable to key
reinstallation (CVE-2017-13082) by passively monitoring FT reassociation
frames for ANonce reuse patterns.

REALISTIC LIMITATION: This module focuses on *detection* -- passive
monitoring for FT reassociation replay patterns -- rather than full active
exploitation.  A complete CVE-2017-13082 attack requires a channel-based
MitM position with two wireless adapters (one to block the original
reassociation response, another to replay a captured one) so that the AP
reinstalls its pairwise key.  This module instead captures FT-related
frames (reassociation requests/responses, FT Action frames, beacons
advertising Mobility Domain / Fast Transition IEs) and flags when the same
ANonce appears in more than one reassociation response for a given
(BSSID, client) pair, which is the observable precondition for
CVE-2017-13082.  It does NOT inject or replay frames itself.

For authorized security testing and research only.
"""

import sys
import os
import argparse
import json
import struct
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Elt, Dot11ReassoReq, Dot11ReassoResp,
    Dot11Auth, RadioTap,
)
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

from utils import validate_mac, validate_interface, require_root, setup_logging


# 802.11r Information Element tag IDs
MDIE_ID = 54   # Mobility Domain IE
FTIE_ID = 55   # Fast Transition IE

# FT Authentication Algorithm number (802.11r)
FT_AUTH_ALG = 2

# FT Action frame constants
FT_ACTION_CATEGORY = 6
FT_ACTION_REQUEST = 1
FT_ACTION_RESPONSE = 2

# FTIE field offsets (after element header: ID + length)
FTIE_MIC_LEN = 16
FTIE_ANONCE_LEN = 32
FTIE_SNONCE_LEN = 32

TEST_MODES = ("reassoc", "pmk-r1", "over-ds", "all")


class FTAttack:
    """Detect 802.11r Fast BSS Transition implementations vulnerable to
    key reinstallation (CVE-2017-13082).

    Passively monitors FT reassociation frames, Mobility Domain / Fast
    Transition information elements, and FT Action frames to identify
    ANonce reuse that indicates a potential key reinstallation
    vulnerability.
    """

    def __init__(self, interface: str, target_bssid: str,
                 channel: Optional[int] = None,
                 target_client: Optional[str] = None,
                 timeout: int = 180,
                 output_dir: str = "captures",
                 test_mode: str = "reassoc",
                 detect_only: bool = False) -> None:
        self.interface: str = interface
        self.target_bssid: str = target_bssid.upper() if target_bssid else target_bssid
        self.target_client: Optional[str] = (
            target_client.upper() if target_client else None
        )
        self.channel: Optional[int] = channel
        self.timeout: int = timeout
        self.output_dir: str = output_dir
        self.test_mode: str = test_mode
        self.detect_only: bool = detect_only
        self.logger = setup_logging("ft_attack")

        # FT support tracking: BSSID -> {mdid, ft_capability, ...}
        self.ft_capable_aps: dict = {}
        # Reassociation tracking: (bssid, client) -> list of ANonce bytes
        self._reassoc_anonces: dict = {}
        # FT Action frame tracking: (bssid, client) -> list of action dicts
        self._ft_action_frames: dict = {}
        # Captured raw frames for analysis/pcap
        self.captured_frames: list = []

        self.vulnerable: bool = False
        self.findings: list = []

        self._stop_event = threading.Event()
        self._start_time: Optional[float] = None
        self._running: bool = False
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # IE parsing helpers
    # -----------------------------------------------------------------
    def _parse_mdie(self, data: bytes) -> dict:
        """Parse a Mobility Domain Information Element (ID 54).

        Args:
            data: Raw bytes of the MDIE body (after the tag ID and length
                bytes), i.e. 3 bytes: MDID (2) + FT Capability Policy (1).

        Returns:
            Dict with 'mdid' (int, 2-byte Mobility Domain ID) and
            'ft_cap_policy' (int, 1-byte FT capability/policy field).
            Returns empty values on parse failure.
        """
        result: dict = {
            "mdid": 0,
            "ft_cap_policy": 0,
        }
        if not data or len(data) < 3:
            return result

        try:
            result["mdid"] = struct.unpack("<H", data[0:2])[0]
            result["ft_cap_policy"] = data[2]
        except Exception as e:
            self.logger.debug("Error parsing MDIE: %s", e)

        return result

    def _parse_ftie(self, data: bytes) -> dict:
        """Parse a Fast Transition Information Element (ID 55).

        Args:
            data: Raw bytes of the FTIE body (after the tag ID and length
                bytes).  Layout: MIC Control (2) + MIC (16) + ANonce (32) +
                SNonce (32) + optional sub-elements (R0KH-ID, R1KH-ID, etc.).

        Returns:
            Dict with 'mic' (bytes), 'anonce' (bytes), 'snonce' (bytes),
            'r0kh_id' (bytes), and 'r1kh_id' (bytes).  Fields default to
            empty bytes on parse failure.
        """
        result: dict = {
            "mic": b"",
            "anonce": b"",
            "snonce": b"",
            "r0kh_id": b"",
            "r1kh_id": b"",
        }

        # Minimum: 2 (MIC Control) + 16 (MIC) + 32 (ANonce) + 32 (SNonce) = 82
        if not data or len(data) < 82:
            return result

        try:
            offset = 2  # skip MIC Control (2 bytes)
            result["mic"] = bytes(data[offset:offset + FTIE_MIC_LEN])
            offset += FTIE_MIC_LEN
            result["anonce"] = bytes(data[offset:offset + FTIE_ANONCE_LEN])
            offset += FTIE_ANONCE_LEN
            result["snonce"] = bytes(data[offset:offset + FTIE_SNONCE_LEN])
            offset += FTIE_SNONCE_LEN

            # Parse optional sub-elements: each has 1-byte ID, 1-byte len, data
            while offset + 2 <= len(data):
                sub_id = data[offset]
                sub_len = data[offset + 1]
                offset += 2
                if offset + sub_len > len(data):
                    break
                sub_data = bytes(data[offset:offset + sub_len])
                if sub_id == 3:    # R0KH-ID
                    result["r0kh_id"] = sub_data
                elif sub_id == 1:  # R1KH-ID
                    result["r1kh_id"] = sub_data
                offset += sub_len
        except Exception as e:
            self.logger.debug("Error parsing FTIE: %s", e)

        return result

    # -----------------------------------------------------------------
    # FT support detection
    # -----------------------------------------------------------------
    def _detect_ft_support(self, packet) -> None:
        """Check a Beacon or Probe Response for 802.11r FT support.

        Parses the Mobility Domain IE (tag 54) and FTIE (tag 55) from
        the packet's information elements.  If found, the AP is recorded
        in ``self.ft_capable_aps``.

        Args:
            packet: Scapy packet (expected to carry Dot11Beacon or
                similar management frame with Dot11Elt layers).
        """
        if not packet.haslayer(Dot11Beacon) and not packet.haslayer(Dot11Elt):
            return

        if not packet.haslayer(Dot11):
            return

        dot11 = packet[Dot11]
        bssid = str(getattr(dot11, "addr3", "") or "").upper()

        if self.target_bssid and bssid != self.target_bssid:
            return

        elt = packet.getlayer(Dot11Elt)
        mdie_data = None
        ftie_data = None

        while elt:
            tag_id = getattr(elt, "ID", None)
            tag_info = getattr(elt, "info", b"")
            if tag_id == MDIE_ID and tag_info:
                mdie_data = bytes(tag_info)
            elif tag_id == FTIE_ID and tag_info:
                ftie_data = bytes(tag_info)
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        if mdie_data:
            mdie = self._parse_mdie(mdie_data)
            with self._lock:
                ap_info = self.ft_capable_aps.setdefault(bssid, {})
                ap_info["mdid"] = mdie["mdid"]
                ap_info["ft_cap_policy"] = mdie["ft_cap_policy"]
                if ftie_data:
                    ftie = self._parse_ftie(ftie_data)
                    ap_info["ftie"] = ftie
                ap_info["first_seen"] = ap_info.get(
                    "first_seen",
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
            self.logger.debug(
                "FT-capable AP detected: %s (MDID=0x%04x)", bssid, mdie["mdid"]
            )

    # -----------------------------------------------------------------
    # FT reassociation tracking
    # -----------------------------------------------------------------
    def _track_ft_reassociation(self, packet) -> None:
        """Track FT reassociation request/response sequences and record
        ANonces from reassociation responses to detect replays.

        Args:
            packet: Scapy packet expected to be a reassociation frame
                carrying FTIE.
        """
        if not packet.haslayer(Dot11):
            return

        dot11 = packet[Dot11]
        is_reassoc_resp = packet.haslayer(Dot11ReassoResp)
        is_reassoc_req = packet.haslayer(Dot11ReassoReq)

        if not is_reassoc_resp and not is_reassoc_req:
            return

        bssid = str(getattr(dot11, "addr3", "") or "").upper()
        if self.target_bssid and bssid != self.target_bssid:
            return

        # Determine client address
        if is_reassoc_resp:
            client = str(getattr(dot11, "addr1", "") or "").upper()
        else:
            client = str(getattr(dot11, "addr2", "") or "").upper()

        if self.target_client and client != self.target_client:
            return

        # Look for FTIE in information elements
        elt = packet.getlayer(Dot11Elt)
        ftie_data = None
        while elt:
            tag_id = getattr(elt, "ID", None)
            tag_info = getattr(elt, "info", b"")
            if tag_id == FTIE_ID and tag_info:
                ftie_data = bytes(tag_info)
                break
            elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None

        if not ftie_data:
            return

        ftie = self._parse_ftie(ftie_data)
        key = (bssid, client)

        # Only reassoc responses carry the AP's ANonce for replay detection
        if is_reassoc_resp and ftie["anonce"]:
            with self._lock:
                anonces = self._reassoc_anonces.setdefault(key, [])
                anonces.append(ftie["anonce"])
            self.logger.debug(
                "FT reassoc response ANonce tracked for %s -> %s", bssid, client
            )

    # -----------------------------------------------------------------
    # FT Action frame monitoring (over-DS)
    # -----------------------------------------------------------------
    def _check_ft_action_frames(self, packet) -> None:
        """Monitor FT Action frames (category 6) for the FT-over-DS variant.

        Args:
            packet: Scapy packet expected to be an Action frame.
        """
        if not packet.haslayer(Dot11):
            return

        dot11 = packet[Dot11]
        # Action frames: type 0 (management), subtype 13
        frame_type = getattr(dot11, "type", None)
        frame_subtype = getattr(dot11, "subtype", None)

        if frame_type != 0 or frame_subtype != 13:
            return

        bssid = str(getattr(dot11, "addr3", "") or "").upper()
        if self.target_bssid and bssid != self.target_bssid:
            return

        # Try to extract the action frame body
        try:
            raw_payload = bytes(dot11.payload) if dot11.payload else b""
        except Exception:
            return

        if len(raw_payload) < 2:
            return

        category = raw_payload[0]
        action_code = raw_payload[1]

        if category != FT_ACTION_CATEGORY:
            return

        if action_code not in (FT_ACTION_REQUEST, FT_ACTION_RESPONSE):
            return

        client = str(getattr(dot11, "addr2", "") or "").upper()
        if self.target_client and client != self.target_client:
            return

        key = (bssid, client)
        action_info = {
            "action_code": action_code,
            "action_type": "request" if action_code == FT_ACTION_REQUEST else "response",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        with self._lock:
            frames = self._ft_action_frames.setdefault(key, [])
            frames.append(action_info)

        self.logger.debug(
            "FT Action frame (%s) for %s -> %s",
            action_info["action_type"], bssid, client,
        )

    # -----------------------------------------------------------------
    # Key reinstallation detection
    # -----------------------------------------------------------------
    def _detect_key_reinstallation(self) -> bool:
        """Check if reassociation responses are replayed (same ANonce reused).

        Scans ``self._reassoc_anonces`` for any (BSSID, client) pair
        that received more than one reassociation response with the same
        ANonce, which is the observable precondition for CVE-2017-13082.

        Returns:
            True if a potential key reinstallation pattern was detected,
            False otherwise.
        """
        detected = False
        with self._lock:
            for key, anonces in self._reassoc_anonces.items():
                if len(anonces) < 2:
                    continue
                seen: set = set()
                for anonce in anonces:
                    if anonce in seen:
                        detected = True
                        finding = {
                            "type": "ft_key_reinstallation",
                            "cve": "CVE-2017-13082",
                            "conversation": key,
                            "detail": (
                                "Duplicate ANonce in FT reassociation "
                                "response — potential key reinstallation"
                            ),
                            "timestamp": datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                        }
                        if finding not in self.findings:
                            self.findings.append(finding)
                    seen.add(anonce)

        if detected:
            self.vulnerable = True
        return detected

    # -----------------------------------------------------------------
    # Packet handling / main loop
    # -----------------------------------------------------------------
    def packet_handler(self, packet) -> None:
        """Process 802.11 frames, filtering for FT-related subtypes.

        Routes packets to the appropriate handler based on the active
        test mode.

        Args:
            packet: Scapy packet from the sniffer.
        """
        try:
            if not packet.haslayer(Dot11):
                return

            dot11 = packet[Dot11]

            # Filter by target BSSID when available
            addrs = {
                str(getattr(dot11, f"addr{i}", "") or "").upper()
                for i in range(1, 4)
            }
            if self.target_bssid and self.target_bssid not in addrs:
                return

            with self._lock:
                self.captured_frames.append(packet)

            # Always check for FT support in beacons/probe responses
            self._detect_ft_support(packet)

            # Route to mode-specific handlers
            if self.test_mode in ("reassoc", "all"):
                self._track_ft_reassociation(packet)

            if self.test_mode in ("pmk-r1", "all"):
                # PMK-R1 hierarchy: also tracked via FTIE in reassoc
                self._track_ft_reassociation(packet)

            if self.test_mode in ("over-ds", "all"):
                self._check_ft_action_frames(packet)

            self._detect_key_reinstallation()

        except Exception as e:
            self.logger.debug("Error processing packet: %s", e)

    def start(self) -> dict:
        """Run FT vulnerability detection and return results.

        Returns:
            Dict summarizing whether the target appears vulnerable,
            the findings observed, FT-capable APs found, and capture
            statistics.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        self._running = True
        self._start_time = time.time()

        self.logger.info("Starting 802.11r FT vulnerability detection")
        self.logger.info("  Interface: %s", self.interface)
        self.logger.info("  Target BSSID: %s", self.target_bssid)
        if self.target_client:
            self.logger.info("  Target client: %s", self.target_client)
        self.logger.info("  Mode: %s", self.test_mode)
        self.logger.info("  Detect-only: %s", self.detect_only)
        self.logger.info("  Timeout: %ds", self.timeout)

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                stop_filter=lambda p: self._stop_event.is_set(),
                timeout=self.timeout,
                store=0,
            )
        except KeyboardInterrupt:
            self.logger.info("Detection interrupted by user")
        except Exception as e:
            self.logger.error("Sniffer error: %s", e)
        finally:
            self._stop_event.set()
            self._running = False

        self._detect_key_reinstallation()

        self.logger.info(
            "FT detection complete. Vulnerable: %s. %d frame(s) captured.",
            self.vulnerable, len(self.captured_frames),
        )

        return {
            "vulnerable": self.vulnerable,
            "findings": self.findings,
            "ft_capable_aps": self.ft_capable_aps,
            "frames_captured": len(self.captured_frames),
            "mode": self.test_mode,
        }

    def save_results(self) -> Optional[str]:
        """Save findings and captured frame data to JSON (and pcap).

        Returns:
            Path to the saved JSON file, or None if there was nothing
            to save.
        """
        if not self.captured_frames and not self.findings:
            self.logger.warning("No results to save")
            return None

        try:
            os.makedirs(self.output_dir, exist_ok=True)
            bssid_safe = (self.target_bssid or "unknown").replace(":", "-")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ft_attack_{bssid_safe}_{timestamp}.json"
            filepath = os.path.join(self.output_dir, filename)

            data = {
                "target_bssid": self.target_bssid,
                "target_client": self.target_client,
                "mode": self.test_mode,
                "vulnerable": self.vulnerable,
                "findings": self.findings,
                "ft_capable_aps": {
                    k: {
                        sk: (sv.hex() if isinstance(sv, bytes) else sv)
                        for sk, sv in v.items()
                    }
                    for k, v in self.ft_capable_aps.items()
                },
                "frames_captured": len(self.captured_frames),
                "timestamp": timestamp,
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)

            if self.captured_frames:
                pcap_path = os.path.join(
                    self.output_dir, f"ft_attack_{bssid_safe}_{timestamp}.pcap"
                )
                try:
                    wrpcap(pcap_path, self.captured_frames)
                except Exception as e:
                    self.logger.debug("Could not write pcap: %s", e)

            self.logger.info("Results saved to %s", filepath)
            return filepath
        except Exception as e:
            self.logger.error("Failed to save results: %s", e)
            return None

    def get_status(self) -> dict:
        """Return current detection status.

        Returns:
            Dict with running state, counts, and elapsed time.
        """
        elapsed = 0.0
        if self._start_time is not None:
            elapsed = time.time() - self._start_time

        with self._lock:
            frame_count = len(self.captured_frames)

        return {
            "running": self._running,
            "interface": self.interface,
            "target_bssid": self.target_bssid,
            "target_client": self.target_client,
            "mode": self.test_mode,
            "detect_only": self.detect_only,
            "frames_captured": frame_count,
            "vulnerable": self.vulnerable,
            "findings_count": len(self.findings),
            "ft_capable_aps": len(self.ft_capable_aps),
            "elapsed_seconds": round(elapsed, 1),
            "timeout": self.timeout,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="802.11r FT Vulnerability Detection - "
                    "Fast BSS Transition key reinstallation testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Passive detection: monitor FT reassociation frames
  sudo python3 ft_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF --detect-only

  # Monitor FT reassociation replay (CVE-2017-13082)
  sudo python3 ft_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -m reassoc

  # Test FT-over-DS variant
  sudo python3 ft_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -m over-ds

  # Run all tests
  sudo python3 ft_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -m all

Note: Interface must be in monitor mode.
      For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-b", "--bssid", required=True,
                        help="Target AP BSSID (MAC address)")
    parser.add_argument("-c", "--client",
                        help="Target client MAC (default: any)")
    parser.add_argument("-ch", "--channel", type=int,
                        help="Channel to listen on")
    parser.add_argument("-t", "--timeout", type=int, default=180,
                        help="Detection timeout in seconds (default: 180)")
    parser.add_argument("-m", "--mode", default="reassoc",
                        choices=list(TEST_MODES),
                        help="Test mode: reassoc (CVE-2017-13082), "
                             "pmk-r1, over-ds, all")
    parser.add_argument("-o", "--output-dir", default="captures",
                        help="Output directory for results (default: captures)")
    parser.add_argument("--detect-only", action="store_true",
                        help="Passive detection only (no injection)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    logger = setup_logging("ft_attack", verbose=args.verbose)

    if not validate_interface(args.interface):
        logger.error("Invalid interface: %s", args.interface)
        sys.exit(1)

    if not validate_mac(args.bssid):
        logger.error("Invalid BSSID format: %s", args.bssid)
        sys.exit(1)

    if args.client and not validate_mac(args.client):
        logger.error("Invalid client MAC format: %s", args.client)
        sys.exit(1)

    attacker = FTAttack(
        interface=args.interface,
        target_bssid=args.bssid,
        channel=args.channel,
        target_client=args.client,
        timeout=args.timeout,
        output_dir=args.output_dir,
        test_mode=args.mode,
        detect_only=args.detect_only,
    )

    if args.verbose:
        attacker.logger = setup_logging("ft_attack", verbose=True)

    results = attacker.start()
    attacker.save_results()

    if results["vulnerable"]:
        print(f"\nTarget appears VULNERABLE to FT key reinstallation "
              f"({args.mode} mode)")
    else:
        print(f"\nNo FT vulnerability detected ({args.mode} mode)")

    sys.exit(0 if results["vulnerable"] else 1)


if __name__ == "__main__":
    main()
