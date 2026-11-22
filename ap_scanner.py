#!/usr/bin/env python3
"""
AP Scanner for Hoover WiFi Security Toolkit
Passively scans for nearby WiFi access points by sniffing beacon and probe response frames
"""

import sys
import os
import argparse
import csv
import json
import threading
import subprocess
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import (
    Dot11, Dot11AssoReq, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeReq,
    Dot11ProbeResp, Dot11ReassoReq, RadioTap,
)
from scapy.sendrecv import sendp, sniff

from utils import validate_interface, check_monitor_mode, require_root, setup_logging, get_channels
from oui_lookup import lookup_vendor


class APScanner:
    # Vendor IE prefix: Wi-Fi Alliance OUI 50:6F:9A + type 28 (OWE Transition Mode)
    OWE_TRANSITION_PREFIX: bytes = b"\x50\x6f\x9a\x1c"

    def __init__(self, interface: str, timeout: int = 30,
                 channel_hop: bool = True, hop_interval: float = 0.5,
                 fixed_channel: Optional[int] = None,
                 output_file: Optional[str] = None,
                 bands: str = "2.4",
                 reveal_hidden: bool = False,
                 deauth_reveal: bool = False) -> None:
        self.interface: str = interface
        self.timeout: int = timeout
        self.channel_hop: bool = channel_hop
        self.hop_interval: float = hop_interval
        self.fixed_channel: Optional[int] = fixed_channel
        self.output_file: Optional[str] = output_file
        self.bands: str = bands
        self.logger = setup_logging("ap_scanner")
        self.access_points: dict[str, dict] = {}
        self._last_akm_suites: list = []
        self._last_rsn_info: dict = {}
        self._last_owe: dict = {}
        self._hop_running: bool = False
        self.reveal_hidden: bool = reveal_hidden
        self.deauth_reveal: bool = deauth_reveal
        self.hidden_aps: dict[str, dict] = {}
        self.revealed_ssids: dict[str, str] = {}

    def packet_handler(self, packet) -> None:
        if packet.haslayer(Dot11AssoReq) or packet.haslayer(Dot11ReassoReq):
            self._handle_association_frame(packet)
            return

        if not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
            return

        try:
            bssid = packet[Dot11].addr3
            if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                return
            bssid = bssid.upper()

            ssid = ""
            channel = None
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace")
                    except Exception:
                        ssid = ""
                elif elt.ID == 3 and elt.info:
                    channel = elt.info[0]
                elt = elt.payload.getlayer(Dot11Elt)

            signal = None
            if packet.haslayer(RadioTap):
                try:
                    signal = packet[RadioTap].dBm_AntSignal
                except Exception:
                    pass

            self._last_akm_suites = []
            self._last_rsn_info = {}
            self._last_owe = {}
            encryption = self._determine_encryption(packet)
            akm_suites = list(self._last_akm_suites)
            rsn_info = self._last_rsn_info
            owe = self._last_owe
            vendor = lookup_vendor(bssid)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if bssid in self.access_points:
                ap = self.access_points[bssid]
                ap["beacon_count"] += 1
                ap["last_seen"] = now
                if signal is not None and (ap["signal"] is None or signal > ap["signal"]):
                    ap["signal"] = signal
                if ssid and not ap["ssid"]:
                    ap["ssid"] = ssid
                if channel and not ap["channel"]:
                    ap["channel"] = channel
            else:
                self.access_points[bssid] = {
                    "ssid": ssid,
                    "channel": channel,
                    "signal": signal,
                    "encryption": encryption,
                    "akm_suites": akm_suites,
                    "pmf_capable": bool(rsn_info.get("pmf_capable", False)),
                    "pmf_required": bool(rsn_info.get("pmf_required", False)),
                    "owe_mode": owe.get("mode"),
                    "owe_transition_bssid": owe.get("bssid"),
                    "owe_transition_ssid": owe.get("ssid"),
                    "vendor": vendor,
                    "first_seen": now,
                    "last_seen": now,
                    "beacon_count": 1,
                }
                self.logger.info(
                    "New AP: %s  SSID: %-32s  CH: %-3s  Enc: %-9s  Signal: %s  Vendor: %s",
                    bssid, ssid or "<hidden>", channel or "?", encryption,
                    f"{signal}dBm" if signal is not None else "?", vendor,
                )

            if self._is_hidden_ssid(ssid):
                if bssid not in self.hidden_aps:
                    self.hidden_aps[bssid] = {"channel": channel, "revealed": False}
                    self.logger.info("Hidden SSID detected at %s (channel %s)", bssid, channel or "?")
                elif channel and not self.hidden_aps[bssid].get("channel"):
                    self.hidden_aps[bssid]["channel"] = channel
            elif bssid in self.hidden_aps and ssid:
                self.hidden_aps[bssid]["revealed"] = True

        except Exception as e:
            self.logger.debug("Error processing packet: %s", e)

    def _handle_association_frame(self, packet) -> None:
        """Extract SSID from (Re)Association Request frames, which carry the
        real SSID even when it was hidden in the AP's beacons."""
        try:
            bssid = packet[Dot11].addr1
            if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                return
            bssid = bssid.upper()

            ssid = ""
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace")
                    except Exception:
                        ssid = ""
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            if not ssid or self._is_hidden_ssid(ssid):
                return

            self.revealed_ssids[bssid] = ssid
            if bssid in self.hidden_aps:
                self.hidden_aps[bssid]["revealed"] = True
            if bssid in self.access_points:
                self.access_points[bssid]["ssid"] = ssid
            self.logger.info("Revealed hidden SSID for %s via association frame: %s", bssid, ssid)
        except Exception as e:
            self.logger.debug("Error processing association frame: %s", e)

    @staticmethod
    def _is_hidden_ssid(ssid: str) -> bool:
        """Return True if the given SSID string indicates a hidden network."""
        if ssid is None or ssid == "":
            return True
        if all(ch == "\x00" for ch in ssid):
            return True
        return False

    def _send_directed_probe(self, bssid: str, channel: int) -> None:
        """Send a wildcard-SSID probe request directly to a specific BSSID."""
        try:
            if channel:
                self._set_channel(channel)
            src_mac = "02:00:00:00:00:01"
            frame = (
                RadioTap()
                / Dot11(addr1=bssid, addr2=src_mac, addr3=bssid)
                / Dot11ProbeReq()
                / Dot11Elt(ID=0, info=b"")
            )
            sendp(frame, iface=self.interface, verbose=False)
            self.logger.debug("Sent directed probe request to %s", bssid)
        except Exception as e:
            self.logger.debug("Error sending directed probe to %s: %s", bssid, e)

    def _send_deauth_for_reveal(self, bssid: str, count: int = 5) -> None:
        """Send deauth frames to force reassociation and leak the SSID."""
        try:
            frame = (
                RadioTap()
                / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
                / Dot11Deauth(reason=7)
            )
            for _ in range(count):
                sendp(frame, iface=self.interface, verbose=False)
            self.logger.debug("Sent %d deauth frame(s) to reveal SSID for %s", count, bssid)
        except Exception as e:
            self.logger.debug("Error sending deauth for %s: %s", bssid, e)

    def _probe_response_handler(self, packet) -> None:
        """Sniff callback for the active reveal phase."""
        try:
            if packet.haslayer(Dot11AssoReq) or packet.haslayer(Dot11ReassoReq):
                self._handle_association_frame(packet)
                return

            if not packet.haslayer(Dot11ProbeResp):
                return

            bssid = packet[Dot11].addr3
            if not bssid:
                return
            bssid = bssid.upper()

            ssid = ""
            elt = packet.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode("utf-8", errors="replace")
                    except Exception:
                        ssid = ""
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            if not ssid or self._is_hidden_ssid(ssid):
                return

            self.revealed_ssids[bssid] = ssid
            if bssid in self.hidden_aps:
                self.hidden_aps[bssid]["revealed"] = True
            if bssid in self.access_points:
                self.access_points[bssid]["ssid"] = ssid
            self.logger.info("Revealed hidden SSID for %s via probe response: %s", bssid, ssid)
        except Exception as e:
            self.logger.debug("Error processing probe response: %s", e)

    def reveal_hidden_ssids(self, timeout: int = 10) -> dict[str, str]:
        """Actively attempt to reveal SSIDs of APs found with hidden SSIDs."""
        targets = [bssid for bssid, info in self.hidden_aps.items()
                   if not info.get("revealed")]
        if not targets:
            self.logger.info("No hidden APs to reveal")
            return dict(self.revealed_ssids)

        self.logger.info("Attempting to reveal SSIDs for %d hidden AP(s)", len(targets))

        for bssid in targets:
            channel = self.hidden_aps[bssid].get("channel")
            self._send_directed_probe(bssid, channel)
            if self.deauth_reveal:
                self._send_deauth_for_reveal(bssid, count=5)

        try:
            sniff(iface=self.interface, prn=self._probe_response_handler,
                  timeout=timeout, store=0)
        except KeyboardInterrupt:
            self.logger.info("Reveal scan interrupted by user")
        except Exception as e:
            self.logger.debug("Error during reveal sniff: %s", e)

        for bssid, ssid in self.revealed_ssids.items():
            if bssid in self.access_points:
                self.access_points[bssid]["ssid"] = ssid

        return dict(self.revealed_ssids)

    def _determine_encryption(self, packet) -> str:
        if not packet.haslayer(Dot11Beacon) and not packet.haslayer(Dot11ProbeResp):
            return "Unknown"

        layer = packet[Dot11Beacon] if packet.haslayer(Dot11Beacon) else packet[Dot11ProbeResp]
        cap = layer.cap if hasattr(layer, "cap") else 0

        has_privacy = bool(cap & 0x0010) if isinstance(cap, int) else "privacy" in str(cap)

        elt = packet.getlayer(Dot11Elt)
        has_rsn = False
        has_wpa = False
        rsn_info = b""
        transition = None
        while elt:
            if elt.ID == 48:
                has_rsn = True
                rsn_info = bytes(elt.info or b"")
            if elt.ID == 221 and elt.info and len(elt.info) >= 4:
                info = bytes(elt.info)
                if info[:3] == b"\x00\x50\xf2" and info[3:4] == b"\x01":
                    has_wpa = True
                elif info[:4] == self.OWE_TRANSITION_PREFIX:
                    transition = self._parse_owe_transition_ie(info) or transition
            elt = elt.payload.getlayer(Dot11Elt)

        if transition:
            self._last_owe = {"mode": "owe_transition",
                              "bssid": transition["bssid"],
                              "ssid": transition["ssid"]}

        if not has_privacy:
            return "Open"

        if has_rsn:
            parsed = self._parse_rsn_ie(rsn_info)
            self._last_rsn_info = parsed
            self._last_akm_suites = parsed["akm_suites"]
            encryption = self._encryption_from_akms(parsed["akm_suites"])
            if "OWE" in parsed["akm_suites"]:
                if transition:
                    encryption = "OWE-Transition"
                else:
                    self._last_owe = {"mode": "owe", "bssid": None, "ssid": None}
            return encryption
        if has_wpa:
            return "WPA"
        return "WEP"

    def _detect_owe_network(self, packet) -> bool:
        """Return True if the frame advertises OWE (AKM 18) or an OWE Transition IE."""
        try:
            elt = packet.getlayer(Dot11Elt)
            while elt:
                info = bytes(elt.info or b"")
                if elt.ID == 48 and "OWE" in self._parse_rsn_ie(info)["akm_suites"]:
                    return True
                if elt.ID == 221 and info[:4] == self.OWE_TRANSITION_PREFIX:
                    return True
                elt = elt.payload.getlayer(Dot11Elt)
        except Exception:
            pass
        return False

    def _parse_owe_transition_ie(self, elt_info: bytes) -> Optional[dict]:
        """Parse an OWE Transition Mode vendor IE body (OUI 50:6F:9A, type 28).

        Layout: OUI(3) type(1) BSSID(6) SSID-len(1) SSID(n) [op-class(1) channel(1)].
        """
        try:
            data = bytes(elt_info or b"")
            if data[:4] != self.OWE_TRANSITION_PREFIX or len(data) < 11:
                return None
            bssid = ":".join(f"{b:02X}" for b in data[4:10])
            ssid_len = data[10]
            if len(data) < 11 + ssid_len:
                return None
            ssid = data[11:11 + ssid_len].decode("utf-8", errors="replace")
            result = {"bssid": bssid, "ssid": ssid}
            rest = data[11 + ssid_len:]
            if len(rest) >= 2:
                result["operating_class"] = rest[0]
                result["channel"] = rest[1]
            return result
        except Exception:
            return None

    @staticmethod
    def _parse_rsn_capabilities(cap_bytes: bytes) -> dict:
        """Parse the 2-byte RSN Capabilities field (little endian)."""
        cap = int.from_bytes(bytes(cap_bytes or b"")[:2], "little")
        return {
            "rsn_capabilities": cap,
            "pre_auth": bool(cap & 0x0001),
            "no_pairwise": bool(cap & 0x0002),
            "ptksa_replay_counters": (cap >> 2) & 0x3,
            "gtksa_replay_counters": (cap >> 4) & 0x3,
            "pmf_required": bool(cap & 0x0040),  # MFPR
            "pmf_capable": bool(cap & 0x0080),   # MFPC
        }

    @staticmethod
    def _encryption_from_akms(akms: list) -> str:
        """Map a list of AKM suite names to an encryption label."""
        akm_set = set(akms)
        has_sae = bool(akm_set & {"SAE", "FT-SAE", "SAE-EXT", "FT-SAE-EXT"})
        has_psk = bool(akm_set & {"PSK", "FT-PSK", "PSK-SHA256"})
        has_8021x = bool(akm_set & {"802.1X", "FT-802.1X", "802.1X-SHA256"})
        has_192 = "802.1X-SUITE-B-192" in akm_set or "802.1X-SUITE-B" in akm_set
        if has_sae and has_psk:
            return "WPA3/WPA2"
        if has_sae:
            return "WPA3"
        if has_192:
            return "WPA3-Enterprise"
        if has_8021x:
            return "WPA2-Enterprise"
        if "OWE" in akm_set:
            return "OWE"
        # PSK, or RSN IE that is truncated/unknown: keep legacy behaviour
        return "WPA2"

    def _parse_rsn_ie(self, rsn_data: bytes) -> dict:
        """Parse an RSN IE body (after tag and length bytes)."""
        result = {"akm_suites": [], "pairwise_ciphers": [], "group_cipher": ""}
        cipher_names = {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104",
                        8: "GCMP", 9: "GCMP-256", 10: "CCMP-256"}
        akm_names = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK",
                     5: "802.1X-SHA256", 6: "PSK-SHA256", 8: "SAE",
                     9: "FT-SAE", 11: "802.1X-SUITE-B", 12: "SAE-EXT",
                     13: "FT-SAE-EXT", 18: "OWE", 24: "SAE-EXT",
                     25: "FT-SAE-EXT"}
        oui = b"\x00\x0f\xac"
        try:
            data = bytes(rsn_data or b"")
            pos = 2  # version
            if len(data) < pos + 4:
                return result
            if data[pos:pos + 3] == oui:
                result["group_cipher"] = cipher_names.get(data[pos + 3], f"Unknown({data[pos + 3]})")
            pos += 4
            if len(data) < pos + 2:
                return result
            count = int.from_bytes(data[pos:pos + 2], "little")
            pos += 2
            for _ in range(count):
                if len(data) < pos + 4:
                    return result
                if data[pos:pos + 3] == oui:
                    result["pairwise_ciphers"].append(
                        cipher_names.get(data[pos + 3], f"Unknown({data[pos + 3]})"))
                pos += 4
            if len(data) < pos + 2:
                return result
            count = int.from_bytes(data[pos:pos + 2], "little")
            pos += 2
            for _ in range(count):
                if len(data) < pos + 4:
                    return result
                if data[pos:pos + 3] == oui:
                    result["akm_suites"].append(
                        akm_names.get(data[pos + 3], f"Unknown({data[pos + 3]})"))
                pos += 4
            if len(data) >= pos + 2:
                result.update(self._parse_rsn_capabilities(data[pos:pos + 2]))
        except Exception:
            pass
        return result

    def _channel_hop_loop(self) -> None:
        channels = get_channels(self.bands)
        idx = 0
        while self._hop_running:
            ch = channels[idx % len(channels)]
            try:
                if validate_interface(self.interface):
                    subprocess.run(
                        ["iwconfig", self.interface, "channel", str(ch)],
                        capture_output=True, text=True, timeout=5,
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            idx += 1
            time.sleep(self.hop_interval)

    def _set_channel(self, channel: int) -> None:
        try:
            if validate_interface(self.interface):
                subprocess.run(
                    ["iwconfig", self.interface, "channel", str(channel)],
                    capture_output=True, text=True, timeout=5,
                )
                self.logger.info("Set channel to %d", channel)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            self.logger.warning("Could not set channel: %s", e)

    def start(self) -> dict[str, dict]:
        self.logger.info("Starting AP scan on %s (timeout: %ds)", self.interface, self.timeout)

        if self.fixed_channel:
            self._set_channel(self.fixed_channel)
        elif self.channel_hop:
            self._hop_running = True
            hop_thread = threading.Thread(target=self._channel_hop_loop, daemon=True)
            hop_thread.start()

        try:
            sniff(iface=self.interface, prn=self.packet_handler,
                  timeout=self.timeout, store=0)
        except KeyboardInterrupt:
            self.logger.info("Scan interrupted by user")
        finally:
            self._hop_running = False

        return self.access_points

    def save_results(self) -> None:
        if not self.output_file or not self.access_points:
            return

        ext = os.path.splitext(self.output_file)[1].lower()
        os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)

        if ext == ".csv":
            with open(self.output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["bssid", "ssid", "channel", "signal", "encryption",
                                 "vendor", "beacon_count", "first_seen", "last_seen"])
                for bssid, ap in self.access_points.items():
                    writer.writerow([
                        bssid, ap["ssid"], ap["channel"], ap["signal"],
                        ap["encryption"], ap["vendor"], ap["beacon_count"],
                        ap["first_seen"], ap["last_seen"],
                    ])
            self.logger.info("Results saved to %s", self.output_file)

        elif ext == ".json":
            with open(self.output_file, "w", encoding="utf-8") as f:
                json.dump(self.access_points, f, indent=2)
            self.logger.info("Results saved to %s", self.output_file)

    def print_results(self) -> None:
        if not self.access_points:
            self.logger.info("No access points found")
            return

        print(f"\n{'='*118}")
        print(f"{'BSSID':<20} {'SSID':<25} {'CH':<5} {'Signal':<8} {'Enc':<10} "
              f"{'PMF':<9} {'Vendor':<20} {'Beacons':<8}")
        print(f"{'='*118}")
        for bssid, ap in sorted(self.access_points.items(),
                                 key=lambda x: x[1].get("signal") or -100, reverse=True):
            sig_str = f"{ap['signal']}dBm" if ap["signal"] is not None else "?"
            if ap.get("pmf_required"):
                pmf = "Required"
            elif ap.get("pmf_capable"):
                pmf = "Capable"
            else:
                pmf = "No"
            enc = ap["encryption"]
            if ap.get("owe_mode") == "owe_transition":
                enc = "OWE-T"
            print(f"{bssid:<20} {(ap['ssid'] or '<hidden>'):<25} "
                  f"{str(ap['channel'] or '?'):<5} {sig_str:<8} "
                  f"{enc:<10} {pmf:<9} {ap['vendor'][:20]:<20} {ap['beacon_count']:<8}")
        print(f"\nTotal: {len(self.access_points)} access points found")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AP Scanner - Discover nearby WiFi access points",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan for 60 seconds with channel hopping
  sudo python3 ap_scanner.py -i wlan0mon -t 60

  # Scan fixed channel 6
  sudo python3 ap_scanner.py -i wlan0mon -ch 6

  # Save results to CSV
  sudo python3 ap_scanner.py -i wlan0mon -o scan_results.csv

Note: Interface must be in monitor mode
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                        help="Scan duration in seconds (default: 30)")
    parser.add_argument("--no-hop", action="store_true",
                        help="Disable channel hopping")
    parser.add_argument("-ch", "--channel", type=int,
                        help="Fixed channel to scan")
    parser.add_argument("--hop-interval", type=float, default=0.5,
                        help="Channel hop interval in seconds (default: 0.5)")
    parser.add_argument("--bands", default="2.4,5",
                        choices=["2.4", "5", "2.4,5", "all"],
                        help="Frequency bands to scan: 2.4, 5, 2.4,5, all (default: 2.4,5)")
    parser.add_argument("-o", "--output",
                        help="Output file path (.csv or .json)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--reveal-hidden", action="store_true",
                        help="Actively probe hidden networks to reveal their SSIDs "
                             "(requires authorization on the target network)")
    parser.add_argument("--deauth-reveal", action="store_true",
                        help="Use deauth to force client reassociation when revealing "
                             "hidden SSIDs (more aggressive; requires authorization)")

    args = parser.parse_args()
    require_root()

    if not check_monitor_mode(args.interface):
        logger = setup_logging("ap_scanner")
        logger.warning("%s may not be in monitor mode", args.interface)
        logger.warning("Enable with: sudo airmon-ng start <interface>")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)

    scanner = APScanner(
        interface=args.interface,
        timeout=args.timeout,
        channel_hop=not args.no_hop,
        hop_interval=args.hop_interval,
        fixed_channel=args.channel,
        output_file=args.output,
        bands=args.bands,
        reveal_hidden=args.reveal_hidden,
        deauth_reveal=args.deauth_reveal,
    )

    scanner.start()

    if (args.reveal_hidden or args.deauth_reveal) and scanner.hidden_aps:
        scanner.reveal_hidden_ssids(timeout=10)

    scanner.print_results()
    scanner.save_results()


if __name__ == "__main__":
    main()
