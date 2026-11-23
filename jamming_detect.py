#!/usr/bin/env python3
"""
RF Jamming Detector for Hoover WiFi Security Toolkit

Passive, defensive (WIDS) module. Monitors a monitor-mode interface for
indicators of RF jamming or denial of service:

  * beacon loss per AP (expected vs received beacons)
  * noise floor / average signal anomalies (RadioTap)
  * deauthentication / disassociation storms
  * simultaneous signal drops across multiple APs (broadband jamming)
  * channels that become unusable (no frames received)

This module only receives frames; it never transmits.
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, RadioTap
from scapy.sendrecv import sniff

from utils import get_channels, require_root, setup_logging, validate_interface

# Typical beacon interval is 100 TU (1 TU = 1024 us) ~= 102.4 ms -> ~9.77/sec.
# 10 beacons/sec is the conventional approximation.
EXPECTED_BEACONS_PER_SEC: float = 10.0
WINDOW_SECONDS: float = 60.0
RECENT_SECONDS: float = 10.0
MIN_BEACON_OBSERVE_SECONDS: float = 5.0
SIGNAL_DROP_DB: float = 15.0
MIN_APS_FOR_DROP: int = 2
MIN_SAMPLES_PER_SIDE: int = 3
ALERT_COOLDOWN_SECONDS: float = 30.0
CHANNEL_DEAD_DWELL_SECONDS: float = 3.0

ALERT_TYPES = ("beacon_loss", "noise_floor", "deauth_storm", "signal_drop", "channel_dead")


class JammingDetector:
    def __init__(
        self,
        interface: str,
        channels: Optional[list[int]] = None,
        beacon_threshold: float = 0.5,
        noise_threshold: int = -50,
        deauth_threshold: int = 50,
        scan_interval: float = 1.0,
        timeout: int = 0,
        output_dir: str = "captures",
    ) -> None:
        self.interface: str = interface
        self.channels: list[int] = list(channels) if channels else get_channels("2.4")
        self.hopping: bool = len(self.channels) > 1
        self.beacon_threshold: float = beacon_threshold
        self.noise_threshold: int = noise_threshold
        self.deauth_threshold: int = deauth_threshold
        self.scan_interval: float = scan_interval
        self.timeout: int = timeout
        self.output_dir: str = output_dir
        self.logger = setup_logging("jamming_detect")

        self.window: float = WINDOW_SECONDS
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        self._beacons: dict[str, deque] = {}  # bssid -> deque[ts]
        self._beacon_channel: dict[str, Optional[int]] = {}
        self._beacon_first_seen: dict[str, float] = {}
        self._signals: dict[str, deque] = {}  # bssid -> deque[(ts, dbm)]
        self._noise: deque = deque()  # (ts, dbm)
        self._deauths: deque = deque()  # ts
        self._dwell: dict[int, deque] = {}  # channel -> deque[(start, end)]
        self._channel_frames: dict[int, deque] = {}  # channel -> deque[ts]
        self._channel_ever_active: set[int] = set()
        self._channel_dead: set[int] = set()
        self._dwell_start: Optional[float] = None
        self._current_channel: Optional[int] = None if self.hopping else self.channels[0]
        self._start_time: Optional[float] = None
        self._baseline_noise: Optional[float] = None

        self.total_frames: int = 0
        self.alerts: list[dict] = []
        self._last_alert: dict[tuple, float] = {}
        self._running: bool = False
        self._hop_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _now() -> float:
        return time.time()

    def _prune(self, now: float) -> None:
        """Drop samples older than the sliding window. Caller holds the lock."""
        cutoff = now - self.window
        for dq in self._beacons.values():
            while dq and dq[0] < cutoff:
                dq.popleft()
        for dq in self._signals.values():
            while dq and dq[0][0] < cutoff:
                dq.popleft()
        while self._noise and self._noise[0][0] < cutoff:
            self._noise.popleft()
        while self._deauths and self._deauths[0] < cutoff:
            self._deauths.popleft()
        for dq in self._channel_frames.values():
            while dq and dq[0] < cutoff:
                dq.popleft()
        for dq in self._dwell.values():
            while dq and dq[0][1] < cutoff:
                dq.popleft()

    # ------------------------------------------------------- packet processing
    def packet_handler(self, packet) -> None:
        """Process every captured frame."""
        try:
            if not packet.haslayer(Dot11):
                return
        except Exception:
            return

        with self._lock:
            self.total_frames += 1
            ch = self._current_channel
            if ch is not None:
                self._channel_frames.setdefault(ch, deque()).append(self._now())
                self._channel_ever_active.add(ch)
                self._channel_dead.discard(ch)

        if packet.haslayer(Dot11Beacon):
            self._track_beacons(packet)
        if packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas):
            self._track_deauth_frames(packet)
        self._track_signal_levels(packet)

    def _track_beacons(self, packet) -> None:
        bssid = packet[Dot11].addr3 or packet[Dot11].addr2
        if not isinstance(bssid, str):
            return
        bssid = bssid.upper()
        now = self._now()
        with self._lock:
            self._beacons.setdefault(bssid, deque()).append(now)
            self._beacon_first_seen.setdefault(bssid, now)
            if self._current_channel is not None:
                self._beacon_channel[bssid] = self._current_channel

    def _track_signal_levels(self, packet) -> None:
        try:
            if not packet.haslayer(RadioTap):
                return
            rt = packet[RadioTap]
        except Exception:
            return
        signal = getattr(rt, "dBm_AntSignal", None)
        noise = getattr(rt, "dBm_AntNoise", None)
        now = self._now()
        with self._lock:
            if isinstance(signal, (int, float)) and not isinstance(signal, bool):
                src = packet[Dot11].addr2
                if isinstance(src, str):
                    # Only per-AP: beacons / probe responses carry the AP as addr2
                    if packet.haslayer(Dot11Beacon):
                        self._signals.setdefault(src.upper(), deque()).append((now, float(signal)))
            if isinstance(noise, (int, float)) and not isinstance(noise, bool):
                self._noise.append((now, float(noise)))

    def _track_deauth_frames(self, packet) -> None:
        with self._lock:
            self._deauths.append(self._now())

    # ------------------------------------------------------------ computations
    def _dwell_seconds(self, channel: Optional[int], since: float, now: float) -> float:
        """Seconds spent listening on a channel since `since`. Caller holds lock."""
        if channel is None or not self.hopping:
            start = max(since, self._start_time or since)
            return max(0.0, now - start)
        total = 0.0
        for s, e in self._dwell.get(channel, ()):
            s, e = max(s, since), min(e, now)
            if e > s:
                total += e - s
        if self._current_channel == channel and self._dwell_start is not None:
            s = max(self._dwell_start, since)
            if now > s:
                total += now - s
        return total

    def _calculate_beacon_loss(self, bssid: str) -> float:
        """Return beacon loss ratio (0.0-1.0) for an AP over the sliding window."""
        bssid = bssid.upper()
        now = self._now()
        with self._lock:
            ts = self._beacons.get(bssid)
            first = self._beacon_first_seen.get(bssid)
            if not ts or first is None:
                return 0.0
            since = max(now - self.window, first)
            observed = self._dwell_seconds(self._beacon_channel.get(bssid), since, now)
            if observed < MIN_BEACON_OBSERVE_SECONDS:
                return 0.0
            received = sum(1 for t in ts if t >= since)
            expected = EXPECTED_BEACONS_PER_SEC * observed
            if expected <= 0:
                return 0.0
            return max(0.0, min(1.0, 1.0 - received / expected))

    def _detect_noise_anomaly(self) -> bool:
        """True if noise floor exceeds threshold, or mean AP signal dropped sharply."""
        now = self._now()
        with self._lock:
            recent = [v for t, v in self._noise if t >= now - RECENT_SECONDS]
            if len(recent) >= MIN_SAMPLES_PER_SIDE:
                if statistics.fmean(recent) > self.noise_threshold:
                    return True
            recent_sig: list[float] = []
            older_sig: list[float] = []
            for dq in self._signals.values():
                for t, v in dq:
                    (recent_sig if t >= now - RECENT_SECONDS else older_sig).append(v)
        if len(recent_sig) >= MIN_SAMPLES_PER_SIDE and len(older_sig) >= MIN_SAMPLES_PER_SIDE:
            return statistics.fmean(older_sig) - statistics.fmean(recent_sig) >= SIGNAL_DROP_DB
        return False

    def _detect_deauth_storm(self) -> bool:
        """True if deauth/disassoc frames in the last 60s exceed threshold."""
        now = self._now()
        with self._lock:
            count = sum(1 for t in self._deauths if t >= now - 60.0)
        return count >= self.deauth_threshold

    def _dropped_aps(self) -> list[str]:
        now = self._now()
        dropped: list[str] = []
        with self._lock:
            for bssid, dq in self._signals.items():
                recent = [v for t, v in dq if t >= now - RECENT_SECONDS]
                older = [v for t, v in dq if t < now - RECENT_SECONDS]
                if len(recent) < MIN_SAMPLES_PER_SIDE or len(older) < MIN_SAMPLES_PER_SIDE:
                    continue
                if statistics.fmean(older) - statistics.fmean(recent) >= SIGNAL_DROP_DB:
                    dropped.append(bssid)
        return dropped

    def _detect_signal_drop(self) -> bool:
        """True if multiple APs show a simultaneous signal drop."""
        return len(self._dropped_aps()) >= MIN_APS_FOR_DROP

    # --------------------------------------------------------------- alerting
    def _generate_alert(self, alert_type: str, details: dict) -> None:
        """Create, log and store an alert (rate-limited per type/channel)."""
        channel = details.get("channel", self._current_channel)
        severity = details.get("severity", "medium")
        key = (alert_type, channel)
        now = self._now()
        with self._lock:
            last = self._last_alert.get(key)
            if last is not None and now - last < ALERT_COOLDOWN_SECONDS:
                return
            self._last_alert[key] = now
            alert = {
                "timestamp": datetime.now().isoformat(),
                "type": alert_type,
                "severity": severity,
                "channel": channel,
                "details": {k: v for k, v in details.items() if k not in ("severity", "channel")},
            }
            self.alerts.append(alert)
        self.logger.warning(
            "ALERT [%s/%s] ch=%s %s", alert_type, severity, channel, alert["details"]
        )

    def _run_checks(self) -> None:
        """Evaluate all detectors once."""
        with self._lock:
            bssids = list(self._beacons.keys())
        for bssid in bssids:
            loss = self._calculate_beacon_loss(bssid)
            if loss >= self.beacon_threshold:
                self._generate_alert(
                    "beacon_loss",
                    {
                        "severity": "high" if loss >= 0.8 else "medium",
                        "channel": self._beacon_channel.get(bssid),
                        "bssid": bssid,
                        "loss_ratio": round(loss, 3),
                        "threshold": self.beacon_threshold,
                    },
                )
        if self._detect_noise_anomaly():
            self._generate_alert(
                "noise_floor",
                {
                    "severity": "high",
                    "noise_threshold": self.noise_threshold,
                },
            )
        if self._detect_deauth_storm():
            with self._lock:
                count = len(self._deauths)
            self._generate_alert(
                "deauth_storm",
                {
                    "severity": "high",
                    "frames_per_min": count,
                    "threshold": self.deauth_threshold,
                },
            )
        dropped = self._dropped_aps()
        if len(dropped) >= MIN_APS_FOR_DROP:
            self._generate_alert(
                "signal_drop",
                {
                    "severity": "high",
                    "affected_aps": dropped,
                    "drop_db_threshold": SIGNAL_DROP_DB,
                },
            )
        self._check_dead_channels()

    def _check_dead_channels(self) -> None:
        now = self._now()
        dead: list[int] = []
        with self._lock:
            for ch in self.channels:
                if ch not in self._channel_ever_active:
                    continue
                since = now - self.window
                if self._dwell_seconds(ch, since, now) < CHANNEL_DEAD_DWELL_SECONDS:
                    continue
                if not any(t >= since for t in self._channel_frames.get(ch, ())):
                    dead.append(ch)
                    self._channel_dead.add(ch)
        for ch in dead:
            self._generate_alert("channel_dead", {"severity": "medium", "channel": ch})

    # ------------------------------------------------------------ channel hop
    def _set_channel(self, channel: int) -> None:
        try:
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(channel)],
                capture_output=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    def _channel_hop_thread(self) -> None:
        """Hop through channels, recording dwell time on each."""
        if not self.hopping:
            return
        idx = 0
        while not self._stop_event.is_set():
            ch = self.channels[idx % len(self.channels)]
            now = self._now()
            with self._lock:
                if self._current_channel is not None and self._dwell_start is not None:
                    self._dwell.setdefault(self._current_channel, deque()).append(
                        (self._dwell_start, now)
                    )
                self._current_channel = ch
                self._dwell_start = now
            self._set_channel(ch)
            idx += 1
            self._stop_event.wait(self.scan_interval)

    # ---------------------------------------------------------------- control
    def start(self) -> dict:
        """Monitor until stopped or timeout; return final status."""
        self._running = True
        self._stop_event.clear()
        self._start_time = self._now()
        if not self.hopping:
            self._set_channel(self.channels[0])
        self.logger.info("Jamming detection on %s (channels: %s)", self.interface, self.channels)

        if self.hopping:
            self._hop_thread = threading.Thread(target=self._channel_hop_thread, daemon=True)
            self._hop_thread.start()

        next_check = self._now() + self.scan_interval
        try:
            while not self._stop_event.is_set():
                if self.timeout and self._now() - self._start_time >= self.timeout:
                    break
                try:
                    sniff(
                        iface=self.interface,
                        prn=self.packet_handler,
                        store=False,
                        timeout=min(self.scan_interval, 1.0),
                        stop_filter=lambda _p: self._stop_event.is_set(),
                    )
                except Exception as e:  # noqa: BLE001
                    self.logger.error("Sniff error: %s", e)
                    break
                if self._now() >= next_check:
                    self._prune(self._now())
                    self._run_checks()
                    next_check = self._now() + self.scan_interval
        except KeyboardInterrupt:
            self.logger.info("Interrupted")
        finally:
            self.stop()
        self.save_results()
        return self.get_status()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()

    # ---------------------------------------------------------------- results
    def get_status(self) -> dict:
        now = self._now()
        with self._lock:
            return {
                "interface": self.interface,
                "running": self._running,
                "channels": list(self.channels),
                "current_channel": self._current_channel,
                "total_frames": self.total_frames,
                "tracked_aps": len(self._beacons),
                "deauth_frames_last_min": sum(1 for t in self._deauths if t >= now - 60.0),
                "dead_channels": sorted(self._channel_dead),
                "alert_count": len(self.alerts),
                "elapsed": round(now - self._start_time, 1) if self._start_time else 0.0,
            }

    def get_alerts(self) -> list[dict]:
        with self._lock:
            return [dict(a) for a in self.alerts]

    def save_results(self) -> Optional[str]:
        """Save status and alerts to a JSON file; return its path or None."""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            path = os.path.join(
                self.output_dir, f"jamming_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            data = {
                "status": self.get_status(),
                "settings": {
                    "beacon_threshold": self.beacon_threshold,
                    "noise_threshold": self.noise_threshold,
                    "deauth_threshold": self.deauth_threshold,
                    "scan_interval": self.scan_interval,
                },
                "alerts": self.get_alerts(),
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            self.logger.info("Results saved to %s", path)
            return path
        except OSError as e:
            self.logger.error("Failed to save results: %s", e)
            return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RF jamming detection (passive WIDS module)",
        epilog="Note: Interface must be in monitor mode. Receive-only; nothing is transmitted.",
    )
    parser.add_argument("-i", "--interface", required=True, help="Monitor-mode interface")
    parser.add_argument("-c", "--channels", help="Comma-separated channels, e.g. 1,6,11")
    parser.add_argument(
        "--beacon-threshold",
        type=float,
        default=0.5,
        help="Beacon loss ratio to alert (default: 0.5)",
    )
    parser.add_argument(
        "--noise-threshold", type=int, default=-50, help="Noise floor dBm threshold (default: -50)"
    )
    parser.add_argument(
        "--deauth-threshold", type=int, default=50, help="Deauth frames/min for storm (default: 50)"
    )
    parser.add_argument(
        "--scan-interval",
        type=float,
        default=1.0,
        help="Check/hop interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=0,
        help="Run time in seconds, 0 = unlimited (default: 0)",
    )
    parser.add_argument(
        "-o", "--output", default="captures", help="Output directory (default: captures)"
    )
    return parser


def main(argv: Optional[list[str]] = None) -> None:
    args = build_parser().parse_args(argv)
    require_root()

    if not validate_interface(args.interface):
        print(f"Invalid interface name: {args.interface}", file=sys.stderr)
        sys.exit(1)

    channels = None
    if args.channels:
        try:
            channels = [int(c) for c in args.channels.split(",") if c.strip()]
        except ValueError:
            print("Invalid channel list", file=sys.stderr)
            sys.exit(1)

    detector = JammingDetector(
        interface=args.interface,
        channels=channels,
        beacon_threshold=args.beacon_threshold,
        noise_threshold=args.noise_threshold,
        deauth_threshold=args.deauth_threshold,
        scan_interval=args.scan_interval,
        timeout=args.timeout,
        output_dir=args.output,
    )
    detector.start()


if __name__ == "__main__":
    main()
