#!/usr/bin/env python3
"""
Hoover - WiFi Probe Request Monitor
Captures and analyzes probe requests from nearby wireless devices
"""

import argparse
import csv
import json
import os
import sqlite3
import subprocess
import sys
import threading
from collections import defaultdict
from datetime import datetime
from typing import Optional, TextIO

from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq
from scapy.sendrecv import sniff

from oui_lookup import lookup_vendor
from utils import check_monitor_mode, get_channels, require_root, setup_logging

# ANSI color codes
_COLORS: dict[str, str] = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _color(name: str, text: str, use_color: bool = True) -> str:
    """Wrap text in ANSI color codes if color output is enabled."""
    if not use_color:
        return text
    return f"{_COLORS.get(name, '')}{text}{_COLORS['reset']}"


class OutputWriter:
    """Handles writing probe data to various output formats."""

    def __init__(self, filepath: str, logger: object) -> None:
        self.filepath: str = filepath
        self.logger = logger
        self._csv_file: Optional[TextIO] = None
        self._csv_writer: Optional[csv.writer] = None
        self._json_file: Optional[TextIO] = None
        self._db_conn: Optional[sqlite3.Connection] = None

        ext = os.path.splitext(filepath)[1].lower()
        if ext == ".csv":
            self._init_csv()
        elif ext == ".json":
            self._init_json()
        elif ext in (".db", ".sqlite"):
            self._init_sqlite()
        else:
            self.logger.error("Unsupported output format: %s (use .csv, .json, .db, or .sqlite)", ext)
            sys.exit(1)

    def _init_csv(self) -> None:
        self._csv_file = open(self.filepath, "a", newline="", encoding="utf-8")
        self._csv_writer = csv.writer(self._csv_file)
        # Write header if file is empty
        if os.path.getsize(self.filepath) == 0:
            self._csv_writer.writerow(["timestamp", "client_mac", "vendor", "ssid", "signal_dbm"])
            self._csv_file.flush()

    def _init_json(self) -> None:
        self._json_file = open(self.filepath, "a", encoding="utf-8")

    def _init_sqlite(self) -> None:
        self._db_conn = sqlite3.connect(self.filepath, check_same_thread=False)
        self._db_conn.execute("""
            CREATE TABLE IF NOT EXISTS probes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_mac TEXT NOT NULL,
                vendor TEXT,
                ssid TEXT NOT NULL,
                signal_dbm INTEGER
            )
        """)
        self._db_conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_probes_client_mac ON probes (client_mac)
        """)
        self._db_conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_probes_ssid ON probes (ssid)
        """)
        self._db_conn.commit()

    def write(self, timestamp: str, client_mac: str, vendor: str,
              ssid: str, signal_dbm: Optional[int]) -> None:
        """Write a probe record to the output file."""
        if self._csv_writer and self._csv_file:
            self._csv_writer.writerow([timestamp, client_mac, vendor, ssid, signal_dbm])
            self._csv_file.flush()
        elif self._json_file:
            record = {
                "timestamp": timestamp,
                "client_mac": client_mac,
                "vendor": vendor,
                "ssid": ssid,
                "signal_dbm": signal_dbm,
            }
            self._json_file.write(json.dumps(record) + "\n")
            self._json_file.flush()
        elif self._db_conn:
            self._db_conn.execute(
                "INSERT INTO probes (timestamp, client_mac, vendor, ssid, signal_dbm) VALUES (?, ?, ?, ?, ?)",
                (timestamp, client_mac, vendor, ssid, signal_dbm),
            )
            self._db_conn.commit()

    def close(self) -> None:
        """Close output file/connection."""
        if self._csv_file:
            self._csv_file.close()
        if self._json_file:
            self._json_file.close()
        if self._db_conn:
            self._db_conn.close()


class ClientFingerprint:
    """Detailed fingerprint data extracted from a client's probe requests."""

    def __init__(self) -> None:
        self.mac: str = ""
        self.vendor: str = ""
        self.probed_ssids: set[str] = set()
        self.supported_rates: list[float] = []
        self.extended_rates: list[float] = []
        self.ht_capable: bool = False
        self.ht_channel_width_40: bool = False
        self.vht_capable: bool = False
        self.he_capable: bool = False  # 802.11ax / WiFi 6
        self.power_capability: Optional[tuple[int, int]] = None  # (min, max) dBm
        self.supported_channels: list[int] = []
        self.wps_enabled: bool = False
        self.wps_device_name: Optional[str] = None
        self.os_guess: str = "Unknown"
        self.device_type: str = "Unknown"
        self.first_seen: str = ""
        self.last_seen: str = ""
        self.signal_history: list[int] = []
        self.probe_count: int = 0

    def to_dict(self) -> dict:
        """Return a JSON/CSV-serializable representation of this fingerprint."""
        return {
            "mac": self.mac,
            "vendor": self.vendor,
            "probed_ssids": sorted(self.probed_ssids),
            "supported_rates": self.supported_rates,
            "extended_rates": self.extended_rates,
            "ht_capable": self.ht_capable,
            "ht_channel_width_40": self.ht_channel_width_40,
            "vht_capable": self.vht_capable,
            "he_capable": self.he_capable,
            "power_capability": list(self.power_capability) if self.power_capability else None,
            "supported_channels": self.supported_channels,
            "wps_enabled": self.wps_enabled,
            "wps_device_name": self.wps_device_name,
            "os_guess": self.os_guess,
            "device_type": self.device_type,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "signal_history": self.signal_history,
            "probe_count": self.probe_count,
        }


class ProbeMonitor:
    def __init__(self, interface: str, verbose: bool = False,
                 json_output: bool = False, use_color: bool = True,
                 output_writer: Optional[OutputWriter] = None,
                 channel_hop: bool = True, hop_interval: float = 0.25,
                 fixed_channel: Optional[int] = None,
                 bands: str = "2.4",
                 fingerprint_mode: bool = False,
                 fp_output: Optional[str] = None) -> None:
        self.interface: str = interface
        self.verbose: bool = verbose
        self.json_output: bool = json_output
        self.use_color: bool = use_color
        self.output_writer: Optional[OutputWriter] = output_writer
        self.channel_hop: bool = channel_hop
        self.hop_interval: float = hop_interval
        self.fixed_channel: Optional[int] = fixed_channel
        self.bands: str = bands
        self.probes: defaultdict[str, set[str]] = defaultdict(set)
        self.logger = setup_logging("hoover", verbose)
        self._hop_stop = threading.Event()
        self.fingerprints: dict[str, ClientFingerprint] = {}  # MAC -> fingerprint
        self.fingerprint_mode: bool = fingerprint_mode
        self.fp_output: Optional[str] = fp_output

    def _set_channel(self, channel: int) -> None:
        """Set the wireless interface to the specified channel."""
        try:
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(channel)],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _channel_hop_loop(self) -> None:
        """Background thread: cycle through WiFi channels for the configured bands."""
        channels = get_channels(self.bands)
        idx = 0
        while not self._hop_stop.is_set():
            self._set_channel(channels[idx])
            idx = (idx + 1) % len(channels)
            self._hop_stop.wait(self.hop_interval)

    # -----------------------------------------------------------------
    # Client fingerprinting
    # -----------------------------------------------------------------

    def _parse_supported_rates(self, elt_info: bytes) -> list[float]:
        """Parse IE ID=1 Supported Rates: each byte = rate/500kbps, MSB=basic."""
        rates: list[float] = []
        if not elt_info:
            return rates
        for byte in elt_info:
            rates.append((byte & 0x7F) * 0.5)
        return rates

    def _parse_extended_rates(self, elt_info: bytes) -> list[float]:
        """Parse IE ID=50 Extended Supported Rates (same encoding as ID=1)."""
        return self._parse_supported_rates(elt_info)

    def _parse_ht_capabilities(self, elt_info: bytes) -> dict:
        """Parse IE ID=45 HT Capabilities: channel width, SM power save, short GI."""
        if not elt_info or len(elt_info) < 2:
            return {}
        cap_info = elt_info[0] | (elt_info[1] << 8)
        return {
            "ldpc_coding": bool(cap_info & 0x0001),
            "channel_width_40": bool(cap_info & 0x0002),
            "sm_power_save": (cap_info >> 2) & 0x3,
            "greenfield": bool(cap_info & 0x0010),
            "short_gi_20": bool(cap_info & 0x0020),
            "short_gi_40": bool(cap_info & 0x0040),
            "tx_stbc": bool(cap_info & 0x0080),
        }

    def _parse_vht_capabilities(self, elt_info: bytes) -> dict:
        """Parse IE ID=191 VHT Capabilities: max MCS, supported widths."""
        if not elt_info or len(elt_info) < 4:
            return {"vht_capable": False}
        cap_info = int.from_bytes(elt_info[0:4], "little")
        supported_width = (cap_info >> 2) & 0x3
        max_mcs = None
        if len(elt_info) >= 6:
            mcs_map = int.from_bytes(elt_info[4:6], "little")
            max_mcs = mcs_map
        return {
            "vht_capable": True,
            "supported_channel_width": supported_width,
            "max_mcs_map": max_mcs,
        }

    def _parse_he_capabilities(self, elt_info: bytes) -> dict:
        """Parse IE ID=255 (ext ID=35) HE Capabilities element."""
        if not elt_info:
            return {"he_capable": False}
        ext_id = elt_info[0]
        if ext_id == 35:
            return {"he_capable": True}
        return {"he_capable": False}

    def _parse_wps_ie(self, elt_info: bytes) -> dict:
        """Parse WPS IE (ID=221, OUI 00:50:F2:04): device name, model, manufacturer."""
        result: dict = {
            "wps_enabled": False,
            "device_name": None,
            "manufacturer": None,
            "model_name": None,
            "model_number": None,
        }
        if not elt_info or len(elt_info) < 4:
            return result

        oui = bytes(elt_info[0:3])
        vendor_type = elt_info[3]
        if oui != b"\x00\x50\xf2" or vendor_type != 4:
            return result

        result["wps_enabled"] = True
        attr_map = {
            0x1011: "device_name",
            0x1021: "manufacturer",
            0x1023: "model_name",
            0x1024: "model_number",
        }
        data = bytes(elt_info[4:])
        idx = 0
        while idx + 4 <= len(data):
            attr_type = int.from_bytes(data[idx:idx + 2], "big")
            attr_len = int.from_bytes(data[idx + 2:idx + 4], "big")
            value = data[idx + 4:idx + 4 + attr_len]
            if attr_type in attr_map:
                try:
                    result[attr_map[attr_type]] = value.decode("utf-8", errors="ignore")
                except Exception:
                    pass
            idx += 4 + attr_len
        return result

    def _parse_power_capability(self, elt_info: bytes) -> tuple[int, int]:
        """Parse IE ID=33: min_power, max_power (signed int8 dBm)."""
        if not elt_info or len(elt_info) < 2:
            return (0, 0)

        def _signed8(val: int) -> int:
            return val - 256 if val >= 128 else val

        return (_signed8(elt_info[0]), _signed8(elt_info[1]))

    def _guess_os(self, fingerprint: "ClientFingerprint") -> str:
        """Heuristic OS detection from rate sets, IE ordering, and OUI."""
        vendor = fingerprint.vendor

        if vendor == "Apple":
            return "iOS/macOS"

        android_vendors = {
            "Samsung", "Google", "Xiaomi", "OnePlus", "Huawei",
            "LG", "Motorola", "Sony",
        }
        if vendor in android_vendors:
            return "Android"

        if vendor == "Microsoft":
            return "Windows"

        if fingerprint.wps_enabled and vendor in ("TP-Link", "Netgear", "Realtek", "Broadcom"):
            return "Linux"

        return "Unknown"

    def _guess_device_type(self, fingerprint: "ClientFingerprint") -> str:
        """Classify as phone/laptop/IoT/tablet from capabilities + vendor."""
        vendor = fingerprint.vendor

        iot_vendors = {"Espressif", "Raspberry Pi"}
        phone_vendors = {
            "Apple", "Samsung", "Google", "Xiaomi", "OnePlus", "Huawei",
            "LG", "Motorola", "Sony",
        }
        laptop_vendors = {"Intel", "Dell", "HP", "Broadcom", "Realtek", "Qualcomm"}

        if vendor in iot_vendors:
            return "IoT"

        if vendor in phone_vendors:
            return "Phone"

        if vendor in laptop_vendors:
            return "Laptop"

        if not fingerprint.ht_capable and not fingerprint.vht_capable and not fingerprint.he_capable:
            return "IoT"

        return "Unknown"

    def fingerprint_client(self, packet: object) -> Optional["ClientFingerprint"]:
        """Extract a full client fingerprint from a probe request's IEs."""
        if not packet.haslayer(Dot11ProbeReq):
            return None

        try:
            client_mac: str = packet[Dot11].addr2
        except Exception:
            return None

        if not client_mac:
            return None

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        fp = self.fingerprints.get(client_mac)
        if fp is None:
            fp = ClientFingerprint()
            fp.mac = client_mac
            fp.vendor = lookup_vendor(client_mac)
            fp.first_seen = timestamp
            self.fingerprints[client_mac] = fp

        fp.last_seen = timestamp
        fp.probe_count += 1

        if hasattr(packet, "dBm_AntSignal") and packet.dBm_AntSignal is not None:
            fp.signal_history.append(packet.dBm_AntSignal)

        # Walk the chain of Dot11Elt information elements.
        elt = None
        try:
            elt = packet.getlayer(Dot11Elt)
        except Exception:
            elt = None

        max_iterations = 64
        seen = 0
        while elt is not None and seen < max_iterations:
            seen += 1
            try:
                eid = elt.ID
                info = elt.info
            except Exception:
                break

            try:
                if eid == 0:
                    ssid = info.decode("utf-8", errors="ignore") if info else ""
                    if ssid:
                        fp.probed_ssids.add(ssid)
                elif eid == 1:
                    fp.supported_rates = self._parse_supported_rates(info)
                elif eid == 50:
                    fp.extended_rates = self._parse_extended_rates(info)
                elif eid == 33:
                    fp.power_capability = self._parse_power_capability(info)
                elif eid == 36:
                    channels: list[int] = []
                    for i in range(0, len(info) - 1, 2):
                        first_channel = info[i]
                        num_channels = info[i + 1]
                        channels.extend(range(first_channel, first_channel + num_channels))
                    fp.supported_channels = channels
                elif eid == 45:
                    ht = self._parse_ht_capabilities(info)
                    if ht:
                        fp.ht_capable = True
                        fp.ht_channel_width_40 = ht.get("channel_width_40", False)
                elif eid == 191:
                    vht = self._parse_vht_capabilities(info)
                    fp.vht_capable = vht.get("vht_capable", False)
                elif eid == 255:
                    he = self._parse_he_capabilities(info)
                    if he.get("he_capable"):
                        fp.he_capable = True
                elif eid == 221:
                    wps = self._parse_wps_ie(info)
                    if wps.get("wps_enabled"):
                        fp.wps_enabled = True
                        fp.wps_device_name = wps.get("device_name")
            except Exception as e:
                if self.verbose:
                    self.logger.debug("Error parsing IE %s: %s", eid, e)

            try:
                next_elt = elt.payload.getlayer(Dot11Elt)
            except Exception:
                next_elt = None
            if next_elt is elt:
                break
            elt = next_elt

        fp.os_guess = self._guess_os(fp)
        fp.device_type = self._guess_device_type(fp)
        return fp

    def get_fingerprints(self) -> dict:
        """Return all client fingerprints as serializable dicts."""
        return {mac: fp.to_dict() for mac, fp in self.fingerprints.items()}

    def print_fingerprint_summary(self) -> None:
        """Print a formatted fingerprint table."""
        print("\n" + "=" * 70)
        print(_color("bold", "CLIENT FINGERPRINTS", self.use_color))
        print("=" * 70)

        if not self.fingerprints:
            print("No fingerprints collected.")
            return

        for mac, fp in self.fingerprints.items():
            print(f"\n{mac} ({fp.vendor})")
            print(f"  OS Guess:     {fp.os_guess}")
            print(f"  Device Type:  {fp.device_type}")
            print(f"  Probe Count:  {fp.probe_count}")
            print(f"  HT: {fp.ht_capable}  VHT: {fp.vht_capable}  HE (WiFi 6): {fp.he_capable}")
            if fp.power_capability:
                print(f"  Power Capability: {fp.power_capability[0]}/{fp.power_capability[1]} dBm")
            if fp.wps_enabled:
                print(f"  WPS Device Name: {fp.wps_device_name}")
            if fp.probed_ssids:
                print(f"  Probed SSIDs: {', '.join(sorted(fp.probed_ssids))}")

    def _write_fingerprints(self, filepath: str) -> None:
        """Write collected fingerprints to a .json or .csv file."""
        ext = os.path.splitext(filepath)[1].lower()
        fingerprints = self.get_fingerprints()
        try:
            if ext == ".json":
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(fingerprints, f, indent=2)
            elif ext == ".csv":
                with open(filepath, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "mac", "vendor", "os_guess", "device_type", "probe_count",
                        "ht_capable", "vht_capable", "he_capable", "wps_enabled",
                        "wps_device_name", "probed_ssids",
                    ])
                    for mac, fp in fingerprints.items():
                        writer.writerow([
                            mac, fp["vendor"], fp["os_guess"], fp["device_type"],
                            fp["probe_count"], fp["ht_capable"], fp["vht_capable"],
                            fp["he_capable"], fp["wps_enabled"], fp["wps_device_name"],
                            ";".join(fp["probed_ssids"]),
                        ])
            else:
                self.logger.error("Unsupported fingerprint output format: %s", ext)
        except OSError as e:
            self.logger.error("Error writing fingerprint output: %s", e)

    def packet_handler(self, packet: object) -> None:
        """Handle captured WiFi packets."""
        if self.fingerprint_mode and packet.haslayer(Dot11ProbeReq):
            try:
                self.fingerprint_client(packet)
            except Exception as e:
                if self.verbose:
                    self.logger.debug("Error fingerprinting packet: %s", e)

        if packet.haslayer(Dot11ProbeReq):
            try:
                # Extract client MAC address
                client_mac: str = packet[Dot11].addr2

                # Extract SSID from probe request
                ssid: str = packet[Dot11Elt].info.decode("utf-8", errors="ignore")

                # Skip empty SSIDs (broadcast probes)
                if ssid:
                    is_new = ssid not in self.probes[client_mac]
                    self.probes[client_mac].add(ssid)

                    # Get signal strength
                    signal_dbm: Optional[int] = None
                    if hasattr(packet, "dBm_AntSignal"):
                        signal_dbm = packet.dBm_AntSignal

                    # Look up vendor
                    vendor: str = lookup_vendor(client_mac)

                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    timestamp_short = datetime.now().strftime("%H:%M:%S")

                    # Write to output file if configured
                    if self.output_writer:
                        self.output_writer.write(timestamp, client_mac, vendor, ssid, signal_dbm)

                    # JSON stdout mode
                    if self.json_output:
                        record = {
                            "timestamp": timestamp,
                            "client_mac": client_mac,
                            "vendor": vendor,
                            "ssid": ssid,
                            "signal_dbm": signal_dbm,
                            "new": is_new,
                        }
                        print(json.dumps(record), flush=True)
                        return

                    # Colored terminal output
                    if is_new:
                        mac_display = f"{client_mac} ({vendor})"
                        line = f"[{timestamp_short}] {mac_display} -> {ssid}"
                        print(_color("green", line, self.use_color))
                    else:
                        mac_display = f"{client_mac} ({vendor})"
                        line = f"[{timestamp_short}] {mac_display} -> {ssid}"
                        print(_color("yellow", line, self.use_color))

                    if self.verbose and signal_dbm is not None:
                        print(_color("cyan", f"  Signal: {signal_dbm} dBm", self.use_color))

            except Exception as e:
                if self.verbose:
                    self.logger.debug("Error parsing packet: %s", e)

    def start(self) -> None:
        """Start monitoring probe requests."""
        if not self.json_output:
            self.logger.info(
                _color("cyan", f"Starting Hoover on interface {self.interface}", self.use_color)
            )
            self.logger.info(
                _color("cyan", "Monitoring probe requests... (Press Ctrl+C to stop)", self.use_color)
            )
            print(f"\n{'Time':<10} {'Client MAC':<36} {'SSID'}")
            print("-" * 70)

        # Start channel hopping thread if enabled
        hop_thread: Optional[threading.Thread] = None
        if self.channel_hop and self.fixed_channel is None:
            hop_thread = threading.Thread(target=self._channel_hop_loop, daemon=True)
            hop_thread.start()
            if not self.json_output:
                self.logger.info(
                    _color("cyan", f"Channel hopping enabled (interval: {self.hop_interval}s)", self.use_color)
                )
        elif self.fixed_channel is not None:
            self._set_channel(self.fixed_channel)
            if not self.json_output:
                self.logger.info(
                    _color("cyan", f"Fixed channel: {self.fixed_channel}", self.use_color)
                )

        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            self._hop_stop.set()
            if not self.json_output:
                print()
                self.print_summary()
                if self.fingerprint_mode:
                    self.print_fingerprint_summary()
            if self.fingerprint_mode and self.fp_output:
                self._write_fingerprints(self.fp_output)
        except Exception as e:
            self._hop_stop.set()
            self.logger.error(_color("red", f"Error: {e}", self.use_color))
            self.logger.error(
                _color("red", "Make sure the interface is in monitor mode", self.use_color)
            )
            sys.exit(1)
        finally:
            self._hop_stop.set()
            if self.output_writer:
                self.output_writer.close()

    def print_summary(self) -> None:
        """Print summary of captured probes."""
        print("\n" + "=" * 70)
        print(_color("bold", "SUMMARY", self.use_color))
        print("=" * 70)
        print(f"Total clients detected: {len(self.probes)}")
        print("\nProbe requests by client:")

        for client, ssids in self.probes.items():
            vendor = lookup_vendor(client)
            print(f"\n{client} ({vendor}):")
            for ssid in sorted(ssids):
                print(f"  - {ssid}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hoover - WiFi Probe Request Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 hoover.py -i wlan0mon
  sudo python3 hoover.py -i wlan0mon -v
  sudo python3 hoover.py -i wlan0mon --output probes.csv
  sudo python3 hoover.py -i wlan0mon --output probes.json --json
  sudo python3 hoover.py -i wlan0mon --output probes.db
  sudo python3 hoover.py -i wlan0mon --channel 6
  sudo python3 hoover.py -i wlan0mon --no-hop
  sudo python3 hoover.py -i wlan0mon --no-color

Note: Interface must be in monitor mode
        """
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--output", metavar="FILE",
                        help="Output file (.csv, .json, .db, or .sqlite)")
    parser.add_argument("--json", dest="json_output", action="store_true",
                        help="Machine-readable JSON output on stdout")
    parser.add_argument("--no-color", dest="no_color", action="store_true",
                        help="Disable colored terminal output")
    parser.add_argument("-hop", "--channel-hop", dest="channel_hop",
                        action="store_true", default=True,
                        help="Enable channel hopping (default: on)")
    parser.add_argument("--no-hop", dest="channel_hop", action="store_false",
                        help="Disable channel hopping")
    parser.add_argument("--hop-interval", type=float, default=0.25,
                        help="Channel hop dwell time in seconds (default: 0.25)")
    parser.add_argument("--channel", type=int, default=None,
                        help="Fixed WiFi channel (disables channel hopping)")
    parser.add_argument("--bands", default="2.4,5",
                        choices=["2.4", "5", "2.4,5", "all"],
                        help="Frequency bands to scan: 2.4, 5, 2.4,5, all (default: 2.4,5)")
    parser.add_argument("--fingerprint", action="store_true",
                        help="Enable detailed client fingerprinting")
    parser.add_argument("--fp-output", metavar="FILE", dest="fp_output",
                        help="Output fingerprint data to file (.json or .csv)")

    args = parser.parse_args()

    # Check if running as root
    require_root()

    # Determine color mode
    use_color: bool = sys.stdout.isatty() and not args.no_color and not args.json_output

    logger = setup_logging("hoover", args.verbose)

    # Validate interface
    if not check_monitor_mode(args.interface):
        logger.warning(
            _color("yellow", f"{args.interface} may not be in monitor mode", use_color)
        )
        logger.warning(
            _color("yellow", "Enable monitor mode with: sudo airmon-ng start <interface>", use_color)
        )

    # Setup output writer
    output_writer: Optional[OutputWriter] = None
    if args.output:
        output_writer = OutputWriter(args.output, logger)

    # Determine channel hopping settings
    channel_hop = args.channel_hop
    fixed_channel: Optional[int] = args.channel
    if fixed_channel is not None:
        channel_hop = False

    # Start monitoring
    monitor = ProbeMonitor(
        interface=args.interface,
        verbose=args.verbose,
        json_output=args.json_output,
        use_color=use_color,
        output_writer=output_writer,
        channel_hop=channel_hop,
        hop_interval=args.hop_interval,
        fixed_channel=fixed_channel,
        bands=args.bands,
        fingerprint_mode=args.fingerprint,
        fp_output=args.fp_output,
    )
    monitor.start()


if __name__ == "__main__":
    main()
