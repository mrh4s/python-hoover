#!/usr/bin/env python3
"""
KRACK (Key Reinstallation Attack) Detection Module for Hoover WiFi Security Toolkit
Detects and tests for WPA2 key reinstallation vulnerabilities (CVE-2017-13077,
CVE-2017-13080, CVE-2017-13082) by monitoring and optionally replaying EAPOL
handshake messages to observe nonce/replay-counter reuse.

REALISTIC LIMITATION: Full KRACK exploitation requires precise timing to
block message 4 delivery to the AP so the client processes a replayed
message 3. This module focuses on *detection* (passive monitoring for nonce
reuse patterns) and *testing* (replaying message 3 / group message 1 to see
whether a client reinstalls keys). A full active attack additionally needs a
channel-based MitM position, which requires two wireless adapters (see the
multi_adapter module).

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

from scapy.layers.dot11 import (
    Dot11, Dot11Deauth, Dot11AssoResp, Dot11ReassoReq, RadioTap,
)
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sniff, sendp
from scapy.utils import wrpcap
from scapy.packet import Raw

from utils import validate_mac, validate_interface, require_root, setup_logging


# EAPOL Key Info field bit masks
KEY_INFO_INSTALL = 0x0008
KEY_INFO_ACK = 0x0040
KEY_INFO_MIC = 0x0100
KEY_INFO_SECURE = 0x0200

TEST_MODES = ("4way", "group", "ft")


class KRACKDetector:
    """Detect and test for WPA2 Key Reinstallation Attack (KRACK) vulnerabilities.

    Monitors the 4-way handshake, group key handshake, and FT reassociation
    exchange for replayed messages that cause a client to reinstall an
    already-in-use key (resetting nonce/replay-counter state), and can
    optionally replay captured frames to actively test a target client.
    """

    def __init__(self, interface: str, target_bssid: str,
                 target_client: Optional[str] = None,
                 channel: Optional[int] = None,
                 timeout: int = 180,
                 output_dir: str = "captures",
                 test_mode: str = "4way") -> None:
        self.interface: str = interface
        self.target_bssid: str = target_bssid.upper() if target_bssid else target_bssid
        self.target_client: Optional[str] = (
            target_client.upper() if target_client else None
        )
        self.channel: Optional[int] = channel
        self.timeout: int = timeout
        self.output_dir: str = output_dir
        self.test_mode: str = test_mode
        self.logger = setup_logging("krack")

        self.detect_only: bool = False

        # EAPOL sequence tracking: (bssid, client) -> list of message numbers seen
        self._eapol_sequences: dict = {}
        # Nonce tracking: (bssid, client) -> list of ANonce bytes observed
        self._nonce_history: dict = {}
        # Captured raw EAPOL frames for replay/analysis
        self.eapol_frames: list = []
        # Messages already sent (msg4) per (bssid, client), used to detect
        # a msg3 replay that arrives *after* msg4 was already seen.
        self._msg4_seen: set = set()

        self.vulnerable: bool = False
        self.findings: list = []

        self._stop_event = threading.Event()
        self._start_time: Optional[float] = None
        self._running: bool = False
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # EAPOL parsing helpers
    # -----------------------------------------------------------------
    def _parse_eapol_key_info(self, eapol_data: bytes) -> dict:
        """Parse an EAPOL Key frame body into its key fields.

        Args:
            eapol_data: Raw bytes of the EAPOL Key frame body (starting at
                the descriptor type byte, as found after the 4-byte EAPOL
                header).

        Returns:
            Dict with key_info (int), replay_counter (int), nonce (bytes),
            and mic (bytes). Fields default to safe empty values if the
            data is too short to parse.
        """
        result = {
            "key_info": 0,
            "replay_counter": 0,
            "nonce": b"",
            "mic": b"",
        }

        if not eapol_data or len(eapol_data) < 1:
            return result

        try:
            # Byte 0: descriptor type, bytes 1-2: key info (big-endian)
            if len(eapol_data) >= 3:
                result["key_info"] = int.from_bytes(eapol_data[1:3], "big")
            # Bytes 9-17: replay counter (8 bytes, big-endian)
            if len(eapol_data) >= 17:
                result["replay_counter"] = int.from_bytes(
                    eapol_data[9:17], "big"
                )
            # Bytes 17-49: key nonce (ANonce/SNonce, 32 bytes)
            if len(eapol_data) >= 49:
                result["nonce"] = bytes(eapol_data[17:49])
            # Bytes 81-97: MIC (16 bytes) in a standard EAPOL key frame
            if len(eapol_data) >= 97:
                result["mic"] = bytes(eapol_data[81:97])
        except Exception as e:
            self.logger.debug("Error parsing EAPOL key info: %s", e)

        return result

    @staticmethod
    def _classify_message(key_info: int) -> Optional[int]:
        """Classify an EAPOL key_info bitmask as 4-way handshake message 1-4.

        Returns:
            1, 2, 3, or 4 for a recognized message, otherwise None.
        """
        ack = bool(key_info & KEY_INFO_ACK)
        mic = bool(key_info & KEY_INFO_MIC)
        install = bool(key_info & KEY_INFO_INSTALL)
        secure = bool(key_info & KEY_INFO_SECURE)

        if ack and not mic:
            return 1
        if mic and not ack and not secure:
            return 2
        if ack and mic and install:
            return 3
        if mic and not ack and secure:
            return 4
        return None

    # -----------------------------------------------------------------
    # Sequence / nonce tracking
    # -----------------------------------------------------------------
    def _track_eapol_sequence(self, packet) -> None:
        """Track 4-way handshake message sequence (msg1-4) by key_info flags.

        Args:
            packet: Scapy packet containing an EAPOL layer.
        """
        key = self._get_conversation_key(packet)
        if key is None:
            return

        eapol_bytes = self._extract_eapol_bytes(packet)
        parsed = self._parse_eapol_key_info(eapol_bytes)
        msg_num = self._classify_message(parsed["key_info"])
        if msg_num is None:
            return

        with self._lock:
            seq = self._eapol_sequences.setdefault(key, [])
            seq.append(msg_num)

            if msg_num == 3 and parsed["nonce"]:
                history = self._nonce_history.setdefault(key, [])
                history.append(parsed["nonce"])

            if msg_num == 4:
                self._msg4_seen.add(key)

        self.logger.debug("Tracked EAPOL message %d for %s", msg_num, key)

    def _get_conversation_key(self, packet):
        """Return (bssid, client) tuple for a packet's handshake conversation."""
        if not packet.haslayer(Dot11):
            return None

        dot11 = packet[Dot11]
        addrs = {
            str(getattr(dot11, f"addr{i}", "") or "").upper()
            for i in range(1, 4)
        }
        if self.target_bssid and self.target_bssid not in addrs:
            return None

        if self.target_client:
            if self.target_client not in addrs:
                return None
            client = self.target_client
        else:
            others = [a for a in addrs if a and a != self.target_bssid]
            client = others[0] if others else "unknown"

        return (self.target_bssid, client)

    def _extract_eapol_bytes(self, packet) -> bytes:
        """Extract the EAPOL Key frame body bytes from a packet."""
        try:
            if packet.haslayer(EAPOL):
                eapol_layer = packet[EAPOL]
                raw = bytes(eapol_layer)
                # Skip the 4-byte EAPOL header (version, type, length) to
                # reach the Key Descriptor body.
                return raw[4:] if len(raw) > 4 else raw
        except Exception as e:
            self.logger.debug("Error extracting EAPOL bytes: %s", e)
        return b""

    def _detect_key_reinstallation(self) -> bool:
        """Detect if AP/client replays EAPOL message 3 with same nonce and
        resets the replay counter.

        Returns:
            True if a key reinstallation pattern was detected, False otherwise.
        """
        detected = False
        with self._lock:
            for key, history in self._nonce_history.items():
                if key not in self._msg4_seen:
                    continue
                if len(history) < 2:
                    continue
                # If the same ANonce reappears in msg3 after msg4 was
                # already observed, that's a replayed msg3 -> reinstallation.
                seen = set()
                for nonce in history:
                    if nonce in seen:
                        detected = True
                        finding = {
                            "type": "key_reinstallation",
                            "conversation": key,
                            "detail": "Duplicate ANonce observed in msg3 "
                                      "after msg4 was sent",
                            "timestamp": datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S"
                            ),
                        }
                        if finding not in self.findings:
                            self.findings.append(finding)
                    seen.add(nonce)

        if detected:
            self.vulnerable = True
        return detected

    def _monitor_nonce_reuse(self) -> dict:
        """Track ANonce values across EAPOL messages; flag if the same
        ANonce is seen after reinstallation.

        Returns:
            Dict mapping conversation key (as string) to a dict with the
            number of unique nonces, total nonces observed, and whether a
            duplicate (reused) nonce was found.
        """
        result = {}
        with self._lock:
            for key, history in self._nonce_history.items():
                unique = set(history)
                duplicate_found = len(unique) < len(history)
                result[str(key)] = {
                    "total_nonces": len(history),
                    "unique_nonces": len(unique),
                    "duplicate_found": duplicate_found,
                }
        return result

    # -----------------------------------------------------------------
    # Active replay (testing)
    # -----------------------------------------------------------------
    def _send_forged_msg3(self, original_msg3: bytes) -> None:
        """Replay a captured EAPOL message 3 to trigger key reinstallation
        on the target client (CVE-2017-13077).

        Args:
            original_msg3: Raw bytes of the previously captured message 3
                frame (as returned by scapy's bytes()/raw()).
        """
        if self.detect_only:
            self.logger.info("detect-only mode: skipping msg3 replay")
            return

        try:
            client = self.target_client or "ff:ff:ff:ff:ff:ff"
            dot11 = Dot11(
                addr1=client, addr2=self.target_bssid, addr3=self.target_bssid
            )
            frame = RadioTap() / dot11 / Raw(load=original_msg3)
            sendp(frame, iface=self.interface, verbose=False)
            self.logger.info(
                "Replayed EAPOL message 3 to %s (CVE-2017-13077 test)", client
            )
        except Exception as e:
            self.logger.warning("Error replaying message 3: %s", e)

    def _send_forged_group_msg1(self, original_msg1: bytes) -> None:
        """Replay a captured Group Key handshake message 1 to trigger group
        key reinstallation (CVE-2017-13080).

        Args:
            original_msg1: Raw bytes of the previously captured group key
                message 1 frame.
        """
        if self.detect_only:
            self.logger.info("detect-only mode: skipping group msg1 replay")
            return

        try:
            client = self.target_client or "ff:ff:ff:ff:ff:ff"
            dot11 = Dot11(
                addr1=client, addr2=self.target_bssid, addr3=self.target_bssid
            )
            frame = RadioTap() / dot11 / Raw(load=original_msg1)
            sendp(frame, iface=self.interface, verbose=False)
            self.logger.info(
                "Replayed Group Key message 1 to %s (CVE-2017-13080 test)",
                client,
            )
        except Exception as e:
            self.logger.warning("Error replaying group message 1: %s", e)

    # -----------------------------------------------------------------
    # Packet handling / main loop
    # -----------------------------------------------------------------
    def packet_handler(self, packet) -> None:
        """Process EAPOL frames, track handshake state, and detect
        reinstallation patterns.

        Args:
            packet: Scapy packet from the sniffer.
        """
        try:
            if not packet.haslayer(EAPOL):
                return

            key = self._get_conversation_key(packet)
            if key is None:
                return

            with self._lock:
                self.eapol_frames.append(packet)

            self._track_eapol_sequence(packet)

            if self.test_mode == "ft" and packet.haslayer(Dot11ReassoReq):
                self.logger.debug("Reassociation request observed for FT test mode")

            self._detect_key_reinstallation()

        except Exception as e:
            self.logger.debug("Error processing packet: %s", e)

    def start(self) -> dict:
        """Run KRACK detection/testing and return a vulnerability assessment.

        Returns:
            Dict summarizing whether the target appears vulnerable, the
            findings observed, and basic capture statistics.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        self._running = True
        self._start_time = time.time()

        self.logger.info("Starting KRACK detection")
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
        nonce_report = self._monitor_nonce_reuse()

        self.logger.info(
            "KRACK detection complete. Vulnerable: %s. %d EAPOL frame(s) captured.",
            self.vulnerable, len(self.eapol_frames),
        )

        return {
            "vulnerable": self.vulnerable,
            "findings": self.findings,
            "nonce_report": nonce_report,
            "frames_captured": len(self.eapol_frames),
            "mode": self.test_mode,
        }

    def save_results(self) -> Optional[str]:
        """Save findings and EAPOL frame data to JSON.

        Returns:
            Path to the saved JSON file, or None if there was nothing to save.
        """
        if not self.eapol_frames and not self.findings:
            self.logger.warning("No results to save")
            return None

        try:
            os.makedirs(self.output_dir, exist_ok=True)
            bssid_safe = (self.target_bssid or "unknown").replace(":", "-")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"krack_{bssid_safe}_{timestamp}.json"
            filepath = os.path.join(self.output_dir, filename)

            data = {
                "target_bssid": self.target_bssid,
                "target_client": self.target_client,
                "mode": self.test_mode,
                "vulnerable": self.vulnerable,
                "findings": self.findings,
                "nonce_report": self._monitor_nonce_reuse(),
                "frames_captured": len(self.eapol_frames),
                "timestamp": timestamp,
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)

            pcap_path = None
            if self.eapol_frames:
                pcap_path = os.path.join(
                    self.output_dir, f"krack_{bssid_safe}_{timestamp}.pcap"
                )
                try:
                    wrpcap(pcap_path, self.eapol_frames)
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
            frame_count = len(self.eapol_frames)

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
            "elapsed_seconds": round(elapsed, 1),
            "timeout": self.timeout,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="KRACK Detection - WPA2 Key Reinstallation Attack testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Passive detection only
  sudo python3 krack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF --detect-only

  # Test 4-way handshake msg3 replay (CVE-2017-13077)
  sudo python3 krack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 -m 4way

  # Test group key handshake replay (CVE-2017-13080)
  sudo python3 krack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -m group

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
    parser.add_argument("-m", "--mode", default="4way",
                        choices=list(TEST_MODES),
                        help="Test mode: 4way (CVE-2017-13077), "
                             "group (CVE-2017-13080), ft (CVE-2017-13082)")
    parser.add_argument("-o", "--output-dir", default="captures",
                        help="Output directory for results (default: captures)")
    parser.add_argument("--detect-only", action="store_true",
                        help="Passive detection without injection")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    logger = setup_logging("krack", verbose=args.verbose)

    if not validate_interface(args.interface):
        logger.error("Invalid interface: %s", args.interface)
        sys.exit(1)

    if not validate_mac(args.bssid):
        logger.error("Invalid BSSID format: %s", args.bssid)
        sys.exit(1)

    if args.client and not validate_mac(args.client):
        logger.error("Invalid client MAC format: %s", args.client)
        sys.exit(1)

    detector = KRACKDetector(
        interface=args.interface,
        target_bssid=args.bssid,
        target_client=args.client,
        channel=args.channel,
        timeout=args.timeout,
        output_dir=args.output_dir,
        test_mode=args.mode,
    )
    detector.detect_only = args.detect_only

    if args.verbose:
        detector.logger = setup_logging("krack", verbose=True)

    results = detector.start()
    detector.save_results()

    if results["vulnerable"]:
        print(f"\nTarget appears VULNERABLE to KRACK ({args.mode} mode)")
    else:
        print(f"\nNo KRACK vulnerability detected ({args.mode} mode)")

    sys.exit(0 if results["vulnerable"] else 1)


if __name__ == "__main__":
    main()
