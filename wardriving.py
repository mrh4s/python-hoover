#!/usr/bin/env python3
"""
GPS/Wardriving Module for Hoover WiFi Security Toolkit
Combines passive AP scanning with GPS positioning (via gpsd) to build a
georeferenced map of discovered access points. Supports export to JSON,
KML (Google Earth) and Wigle-compatible CSV formats.
For authorized security testing and research only.
"""

import argparse
import csv
import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap
from scapy.sendrecv import sniff

from ap_scanner import APScanner
from oui_lookup import lookup_vendor
from utils import get_channels, require_root, setup_logging, validate_interface


class WardrivingMapper:
    """Georeferenced WiFi access point mapper (wardriving).

    Sniffs beacon/probe response frames while polling a gpsd daemon for
    the current GPS fix, associating each AP sighting with a location so
    the results can be exported to JSON, KML or Wigle-compatible CSV.
    """

    def __init__(
        self,
        interface: str,
        gpsd_host: str = "127.0.0.1",
        gpsd_port: int = 2947,
        output_file: str = "wardriving.json",
        scan_interval: float = 1.0,
        timeout: int = 0,  # 0 = unlimited
        bands: str = "2.4,5",
    ) -> None:
        self.interface: str = interface
        self.gpsd_host: str = gpsd_host
        self.gpsd_port: int = gpsd_port
        self.output_file: str = output_file
        self.scan_interval: float = scan_interval
        self.timeout: int = timeout
        self.bands: str = bands

        self.logger = setup_logging("wardriving")

        self.access_points: dict[str, dict] = {}
        self._lock = threading.Lock()

        self._gpsd_socket: Optional[socket.socket] = None
        self._gpsd_connected: bool = False
        self._current_fix: Optional[dict] = None

        self._gps_running: bool = False
        self._gps_thread: Optional[threading.Thread] = None

        self._hop_running: bool = False
        self._hop_thread: Optional[threading.Thread] = None

        self._encryption_helper = APScanner(interface=interface)

    # -- GPS ----------------------------------------------------------

    def _connect_gpsd(self) -> bool:
        """Connect to gpsd via its JSON protocol on a raw TCP socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.gpsd_host, self.gpsd_port))
            sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
            self._gpsd_socket = sock
            self._gpsd_connected = True
            self.logger.info("Connected to gpsd at %s:%d", self.gpsd_host, self.gpsd_port)
            return True
        except OSError as e:
            self.logger.warning(
                "Could not connect to gpsd at %s:%d: %s", self.gpsd_host, self.gpsd_port, e
            )
            self._gpsd_connected = False
            return False

    def _get_gps_fix(self) -> Optional[dict]:
        """Query gpsd for the current fix (lat, lon, alt, speed, time, satellites)."""
        if not self._gpsd_socket:
            return None
        try:
            data = self._gpsd_socket.recv(4096)
            if not data:
                return None
            for line in data.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except (ValueError, json.JSONDecodeError):
                    continue
                if msg.get("class") == "TPV":
                    mode = msg.get("mode", 0)
                    if mode is None or mode < 2:
                        return None
                    if "lat" not in msg or "lon" not in msg:
                        return None
                    return {
                        "lat": msg.get("lat"),
                        "lon": msg.get("lon"),
                        "alt": msg.get("alt"),
                        "speed": msg.get("speed"),
                        "time": msg.get("time"),
                        "mode": mode,
                        "satellites": msg.get("satellites"),
                    }
            return None
        except (OSError, socket.timeout) as e:
            self.logger.debug("Error reading gpsd fix: %s", e)
            return None

    def _gps_polling_loop(self) -> None:
        """Background thread: poll gpsd continuously, update current position."""
        while self._gps_running:
            fix = self._get_gps_fix()
            if fix is not None:
                with self._lock:
                    self._current_fix = fix
            time.sleep(self.scan_interval)

    # -- Packet handling ------------------------------------------------

    def packet_handler(self, packet) -> None:
        """Handle a beacon/probe response, associating it with the current GPS fix."""
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

            encryption = self._encryption_helper._determine_encryption(packet)
            vendor = lookup_vendor(bssid)
            now = datetime.now().isoformat()

            with self._lock:
                fix = self._current_fix

                if bssid in self.access_points:
                    ap = self.access_points[bssid]
                    ap["last_seen"] = now
                    if ssid and not ap["ssid"]:
                        ap["ssid"] = ssid
                    if channel and not ap["channel"]:
                        ap["channel"] = channel
                    if signal is not None:
                        ap["signal"] = signal
                else:
                    ap = {
                        "bssid": bssid,
                        "ssid": ssid,
                        "encryption": encryption,
                        "channel": channel,
                        "signal": signal,
                        "vendor": vendor,
                        "first_seen": now,
                        "last_seen": now,
                        "locations": [],
                        "best_signal_location": None,
                    }
                    self.access_points[bssid] = ap

                if fix is not None:
                    location = {
                        "lat": fix.get("lat"),
                        "lon": fix.get("lon"),
                        "alt": fix.get("alt"),
                        "signal": signal,
                        "time": now,
                    }
                    ap["locations"].append(location)

                    best = ap.get("best_signal_location")
                    if signal is not None and (
                        best is None or best.get("signal") is None or signal > best["signal"]
                    ):
                        ap["best_signal_location"] = dict(location)

        except Exception as e:
            self.logger.debug("Error processing packet: %s", e)

    # -- Channel hopping -------------------------------------------------

    def _channel_hop_loop(self) -> None:
        """Channel hopping thread (reuses pattern from ap_scanner)."""
        channels = get_channels(self.bands)
        idx = 0
        while self._hop_running:
            ch = channels[idx % len(channels)]
            try:
                if validate_interface(self.interface):
                    subprocess.run(
                        ["iwconfig", self.interface, "channel", str(ch)],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            idx += 1
            time.sleep(0.5)

    # -- Lifecycle ---------------------------------------------------

    def start(self) -> None:
        """Start wardriving: GPS polling + channel hopping + packet sniffing."""
        self.logger.info("Starting wardriving on %s (timeout: %ds)", self.interface, self.timeout)

        if not self._connect_gpsd():
            self.logger.warning("gpsd unavailable; continuing AP scan without GPS data")
        else:
            self._gps_running = True
            self._gps_thread = threading.Thread(target=self._gps_polling_loop, daemon=True)
            self._gps_thread.start()

        self._hop_running = True
        self._hop_thread = threading.Thread(target=self._channel_hop_loop, daemon=True)
        self._hop_thread.start()

        try:
            sniff(
                iface=self.interface, prn=self.packet_handler, timeout=self.timeout or None, store=0
            )
        except KeyboardInterrupt:
            self.logger.info("Wardriving interrupted by user")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop all threads, save data."""
        self._gps_running = False
        self._hop_running = False
        if self._gpsd_socket is not None:
            try:
                self._gpsd_socket.close()
            except OSError:
                pass
            self._gpsd_socket = None
        self.save_results()

    # -- Export --------------------------------------------------------

    def save_results(self) -> str:
        """Save georeferenced AP data to the output file (JSON)."""
        os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)
        with self._lock:
            data = {bssid: dict(ap) for bssid, ap in self.access_points.items()}
        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self.logger.info("Results saved to %s", self.output_file)
        return self.output_file

    def export_kml(self, output_path: str) -> str:
        """Export georeferenced AP data to KML format for Google Earth."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<kml xmlns="http://www.opengis.net/kml/2.2">',
            "<Document>",
            "<name>Hoover Wardriving Results</name>",
        ]

        with self._lock:
            aps = list(self.access_points.values())

        for ap in aps:
            best = ap.get("best_signal_location")
            if not best or best.get("lat") is None or best.get("lon") is None:
                continue
            ssid = ap.get("ssid") or "<hidden>"
            name = self._xml_escape(ssid)
            description = self._xml_escape(
                f"BSSID: {ap.get('bssid')} | Encryption: {ap.get('encryption')} | "
                f"Channel: {ap.get('channel')} | Signal: {best.get('signal')}dBm"
            )
            lines.append("<Placemark>")
            lines.append(f"<name>{name}</name>")
            lines.append(f"<description>{description}</description>")
            lines.append("<Point>")
            lines.append(
                f"<coordinates>{best.get('lon')},{best.get('lat')},{best.get('alt') or 0}</coordinates>"
            )
            lines.append("</Point>")
            lines.append("</Placemark>")

        lines.append("</Document>")
        lines.append("</kml>")

        content = "\n".join(lines)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        self.logger.info("KML exported to %s", output_path)
        return output_path

    def export_csv(self, output_path: str) -> str:
        """Export georeferenced AP data to Wigle-compatible CSV format."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with self._lock:
            aps = list(self.access_points.values())

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            f.write(
                "WigleWifi-1.4,appRelease=hoover,model=hoover,release=1.0,"
                "device=hoover,display=hoover,board=hoover,brand=hoover\n"
            )
            writer = csv.writer(f)
            writer.writerow(
                [
                    "MAC",
                    "SSID",
                    "AuthMode",
                    "FirstSeen",
                    "Channel",
                    "RSSI",
                    "CurrentLatitude",
                    "CurrentLongitude",
                    "AltitudeMeters",
                    "AccuracyMeters",
                    "Type",
                ]
            )
            for ap in aps:
                best = ap.get("best_signal_location") or {}
                writer.writerow(
                    [
                        ap.get("bssid", ""),
                        ap.get("ssid", ""),
                        ap.get("encryption", ""),
                        ap.get("first_seen", ""),
                        ap.get("channel", ""),
                        best.get("signal", ap.get("signal", "")),
                        best.get("lat", ""),
                        best.get("lon", ""),
                        best.get("alt", ""),
                        0,
                        "WIFI",
                    ]
                )
        self.logger.info("Wigle CSV exported to %s", output_path)
        return output_path

    @staticmethod
    def _xml_escape(text: str) -> str:
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )

    # -- Status --------------------------------------------------------

    def get_status(self) -> dict:
        """Return current status with GPS fix and AP count."""
        with self._lock:
            return {
                "interface": self.interface,
                "gpsd_connected": self._gpsd_connected,
                "current_fix": dict(self._current_fix) if self._current_fix else None,
                "ap_count": len(self.access_points),
                "running": self._gps_running or self._hop_running,
            }

    def get_results(self) -> dict:
        """Return all georeferenced AP data."""
        with self._lock:
            return {bssid: dict(ap) for bssid, ap in self.access_points.items()}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wardriving - Build a georeferenced map of nearby WiFi access points "
        "using GPS (via gpsd). For authorized security testing only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Wardrive for 5 minutes, saving JSON
  sudo python3 wardriving.py -i wlan0mon -t 300

  # Export to all formats (json, kml, csv)
  sudo python3 wardriving.py -i wlan0mon -o results.json -f all

Note: Interface must be in monitor mode. gpsd must be running and
reachable (default 127.0.0.1:2947) for GPS-tagged results.
        """,
    )

    parser.add_argument(
        "-i", "--interface", required=True, help="Wireless interface in monitor mode"
    )
    parser.add_argument("--gpsd-host", default="127.0.0.1", help="gpsd host (default: 127.0.0.1)")
    parser.add_argument("--gpsd-port", type=int, default=2947, help="gpsd port (default: 2947)")
    parser.add_argument(
        "-o",
        "--output",
        default="wardriving.json",
        help="Output file path (default: wardriving.json)",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["json", "csv", "kml", "all"],
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--scan-interval",
        type=float,
        default=1.0,
        help="Seconds between GPS samples (default: 1.0)",
    )
    parser.add_argument("--bands", default="2.4,5", help="Frequency bands to scan (default: 2.4,5)")
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=0,
        help="Scan duration in seconds, 0=unlimited (default: 0)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()
    require_root()

    if not validate_interface(args.interface):
        print(f"Invalid interface: {args.interface}", file=sys.stderr)
        sys.exit(1)

    mapper = WardrivingMapper(
        interface=args.interface,
        gpsd_host=args.gpsd_host,
        gpsd_port=args.gpsd_port,
        output_file=args.output,
        scan_interval=args.scan_interval,
        timeout=args.timeout,
        bands=args.bands,
    )

    mapper.start()

    base, _ = os.path.splitext(args.output)
    if args.format in ("kml", "all"):
        mapper.export_kml(base + ".kml")
    if args.format in ("csv", "all"):
        mapper.export_csv(base + ".csv")


if __name__ == "__main__":
    main()
