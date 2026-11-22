#!/usr/bin/env python3
"""
Hoover - WiFi Probe Request Monitor
Captures and analyzes probe requests from nearby wireless devices
"""

import sys
import os
import argparse
import csv
import json
import sqlite3
import threading
import subprocess
from datetime import datetime
from collections import defaultdict
from typing import Optional, TextIO

from scapy.layers.dot11 import Dot11, Dot11ProbeReq, Dot11Elt, RadioTap
from scapy.sendrecv import sniff

from utils import validate_mac, check_monitor_mode, require_root, setup_logging, get_channels
from oui_lookup import lookup_vendor

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


class ProbeMonitor:
    def __init__(self, interface: str, verbose: bool = False,
                 json_output: bool = False, use_color: bool = True,
                 output_writer: Optional[OutputWriter] = None,
                 channel_hop: bool = True, hop_interval: float = 0.25,
                 fixed_channel: Optional[int] = None,
                 bands: str = "2.4") -> None:
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

    def packet_handler(self, packet: object) -> None:
        """Handle captured WiFi packets."""
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
        print(f"\nProbe requests by client:")

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
    )
    monitor.start()


if __name__ == "__main__":
    main()
