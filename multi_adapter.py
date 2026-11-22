#!/usr/bin/env python3
"""
Multi-Adapter Management Module for Hoover WiFi Security Toolkit
Discovers, configures and tracks multiple wireless adapters so that
other attack/scan modules can coordinate roles (monitor, inject, ap,
scan) across several physical NICs.
For authorized security testing and research only.
"""

import sys
import os
import argparse
import glob
import json
import subprocess
import threading
from typing import Optional

from utils import (
    validate_interface,
    setup_logging,
    require_root,
    check_monitor_mode,
)

# No scapy needed -- this is infrastructure/management code

VALID_ROLES = ("monitor", "inject", "ap", "scan")


class MultiAdapterManager:
    """Manage multiple wireless adapters and their assigned roles.

    Tracks a registry of adapters (interface -> role/channel/band info),
    supports auto-discovery of wireless interfaces on the system, and
    can drive mode changes (monitor/managed) and channel assignment via
    `ip` and `iw`.
    """

    def __init__(self, adapters: Optional[list] = None,
                 verbose: bool = False) -> None:
        self.logger = setup_logging("multi_adapter", verbose)
        self.verbose = verbose
        self.lock = threading.Lock()
        self.adapters: dict = {}

        if adapters:
            for entry in adapters:
                self.add_adapter(
                    interface=entry["interface"],
                    role=entry["role"],
                    channel=entry.get("channel"),
                )

    # ------------------------------------------------------------------
    # Registry management
    # ------------------------------------------------------------------
    def add_adapter(self, interface: str, role: str,
                     channel: Optional[int] = None) -> None:
        """Register an adapter with a specific role.

        Args:
            interface: Network interface name (e.g. "wlan0").
            role: One of "monitor", "inject", "ap", "scan".
            channel: Optional starting channel.

        Raises:
            ValueError: If the interface name or role is invalid.
        """
        if not validate_interface(interface):
            raise ValueError(f"Invalid interface name: {interface!r}")
        if role not in VALID_ROLES:
            raise ValueError(
                f"Invalid role: {role!r} (expected one of {VALID_ROLES})"
            )

        with self.lock:
            self.adapters[interface] = {
                "interface": interface,
                "role": role,
                "phy": None,
                "driver": None,
                "modes": [],
                "bands": [],
                "current_mode": None,
                "channel": channel,
                "mac": None,
            }
        self.logger.info("Registered adapter %s with role=%s", interface, role)

    def remove_adapter(self, interface: str) -> None:
        """Unregister an adapter.

        Args:
            interface: Network interface name to remove.
        """
        with self.lock:
            if interface in self.adapters:
                del self.adapters[interface]
                self.logger.info("Removed adapter %s", interface)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------
    def discover_adapters(self) -> list:
        """Auto-detect wireless interfaces via /sys/class/net and iw.

        Returns:
            A list of info dicts for each wireless interface found.
        """
        discovered = []
        wireless_paths = glob.glob("/sys/class/net/*/wireless")
        phy_paths = glob.glob("/sys/class/net/*/phy80211")
        iface_names = set()

        for path in wireless_paths:
            iface_names.add(path.split("/")[-2])
        for path in phy_paths:
            iface_names.add(path.split("/")[-2])

        for iface in sorted(iface_names):
            info = {
                "interface": iface,
                "role": None,
                "phy": self._get_phy_name(iface),
                "driver": self._get_driver(iface),
                "modes": [],
                "bands": [],
                "current_mode": None,
                "channel": None,
                "mac": self._get_mac(iface),
            }
            info["modes"] = self._get_phy_modes(info["phy"])
            discovered.append(info)

        return discovered

    def _get_phy_name(self, interface: str) -> Optional[str]:
        """Read the phy80211 symlink to get the phy name for an interface."""
        path = f"/sys/class/net/{interface}/phy80211"
        try:
            return os.path.basename(os.path.realpath(path))
        except OSError:
            return None

    def _get_driver(self, interface: str) -> Optional[str]:
        """Read the device driver symlink for an interface."""
        path = f"/sys/class/net/{interface}/device/driver"
        try:
            return os.path.basename(os.path.realpath(path))
        except OSError:
            return None

    def _get_mac(self, interface: str) -> Optional[str]:
        """Read the MAC address for an interface from sysfs."""
        path = f"/sys/class/net/{interface}/address"
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return None

    def _get_phy_modes(self, phy: Optional[str]) -> list:
        """Query `iw phy <phy> info` for supported interface modes."""
        if not phy:
            return []
        try:
            result = subprocess.run(
                ["iw", "phy", phy, "info"],
                capture_output=True, text=True, timeout=5,
            )
            modes = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("* managed"):
                    modes.append("managed")
                elif line.startswith("* monitor"):
                    modes.append("monitor")
                elif line.startswith("* AP"):
                    modes.append("AP")
            return modes
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []

    # ------------------------------------------------------------------
    # Mode / channel control
    # ------------------------------------------------------------------
    def set_monitor_mode(self, interface: str) -> bool:
        """Put interface into monitor mode via iw.

        Args:
            interface: Network interface name.

        Returns:
            True if all commands succeeded, False otherwise.
        """
        if not validate_interface(interface):
            return False
        try:
            subprocess.run(["ip", "link", "set", interface, "down"],
                            capture_output=True, text=True, timeout=5, check=True)
            subprocess.run(["iw", "dev", interface, "set", "type", "monitor"],
                            capture_output=True, text=True, timeout=5, check=True)
            subprocess.run(["ip", "link", "set", interface, "up"],
                            capture_output=True, text=True, timeout=5, check=True)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError,
                FileNotFoundError, OSError) as exc:
            self.logger.error("Failed to set monitor mode on %s: %s", interface, exc)
            return False

        with self.lock:
            if interface in self.adapters:
                self.adapters[interface]["current_mode"] = "monitor"
        self.logger.info("Set %s to monitor mode", interface)
        return True

    def set_managed_mode(self, interface: str) -> bool:
        """Restore interface to managed mode.

        Args:
            interface: Network interface name.

        Returns:
            True if all commands succeeded, False otherwise.
        """
        if not validate_interface(interface):
            return False
        try:
            subprocess.run(["ip", "link", "set", interface, "down"],
                            capture_output=True, text=True, timeout=5, check=True)
            subprocess.run(["iw", "dev", interface, "set", "type", "managed"],
                            capture_output=True, text=True, timeout=5, check=True)
            subprocess.run(["ip", "link", "set", interface, "up"],
                            capture_output=True, text=True, timeout=5, check=True)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError,
                FileNotFoundError, OSError) as exc:
            self.logger.error("Failed to set managed mode on %s: %s", interface, exc)
            return False

        with self.lock:
            if interface in self.adapters:
                self.adapters[interface]["current_mode"] = "managed"
        self.logger.info("Set %s to managed mode", interface)
        return True

    def set_channel(self, interface: str, channel: int) -> bool:
        """Set channel on specific adapter.

        Args:
            interface: Network interface name.
            channel: Channel number to set.

        Returns:
            True if the command succeeded, False otherwise.
        """
        if not validate_interface(interface):
            return False
        try:
            subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)],
                            capture_output=True, text=True, timeout=5, check=True)
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError,
                FileNotFoundError, OSError) as exc:
            self.logger.error("Failed to set channel on %s: %s", interface, exc)
            return False

        with self.lock:
            if interface in self.adapters:
                self.adapters[interface]["channel"] = channel
        self.logger.info("Set %s to channel %s", interface, channel)
        return True

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------
    def get_adapter(self, role: str) -> Optional[dict]:
        """Get adapter assigned to a role.

        Args:
            role: Role to search for.

        Returns:
            The adapter dict if found, else None.
        """
        with self.lock:
            for adapter in self.adapters.values():
                if adapter["role"] == role:
                    return adapter
        return None

    def get_monitor_adapter(self) -> Optional[str]:
        """Shortcut: return monitor role interface name."""
        adapter = self.get_adapter("monitor")
        return adapter["interface"] if adapter else None

    def get_inject_adapter(self) -> Optional[str]:
        """Shortcut: return inject role interface name."""
        adapter = self.get_adapter("inject")
        return adapter["interface"] if adapter else None

    # ------------------------------------------------------------------
    # Validation / status
    # ------------------------------------------------------------------
    def validate_all(self) -> dict:
        """Validate all registered adapters exist and are in correct mode.

        Returns:
            Dict mapping interface -> bool (True if valid).
        """
        results = {}
        with self.lock:
            adapters = dict(self.adapters)

        for interface, info in adapters.items():
            if info["role"] in ("monitor", "scan"):
                results[interface] = check_monitor_mode(interface)
            else:
                results[interface] = True
        return results

    def get_status(self) -> dict:
        """Return status of all adapters.

        Returns:
            Dict with adapter registry and summary info.
        """
        with self.lock:
            adapters = {k: dict(v) for k, v in self.adapters.items()}
        return {
            "adapters": adapters,
            "count": len(adapters),
            "monitor": self.get_monitor_adapter(),
            "inject": self.get_inject_adapter(),
        }

    def cleanup(self) -> None:
        """Restore all adapters to managed mode."""
        with self.lock:
            interfaces = list(self.adapters.keys())
        for interface in interfaces:
            self.set_managed_mode(interface)
        self.logger.info("Cleanup complete: all adapters restored to managed mode")


def _parse_adapters_arg(value: str) -> list:
    """Parse a comma-separated interface:role string into adapter dicts."""
    adapters = []
    for pair in value.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if ":" not in pair:
            raise ValueError(f"Invalid adapter spec: {pair!r} (expected iface:role)")
        interface, role = pair.split(":", 1)
        adapters.append({"interface": interface.strip(), "role": role.strip()})
    return adapters


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-Adapter Management for Hoover WiFi Security Toolkit. "
                    "For authorized security testing and research only.",
    )
    parser.add_argument(
        "--adapters",
        help='Comma-separated interface:role pairs (e.g., "wlan0:monitor,wlan1:inject")',
    )
    parser.add_argument(
        "--discover", action="store_true",
        help="Auto-discover and list available wireless adapters",
    )
    parser.add_argument(
        "--setup", action="store_true",
        help="Automatically configure adapter modes based on roles",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging",
    )
    args = parser.parse_args()

    manager = MultiAdapterManager(verbose=args.verbose)

    if args.discover:
        discovered = manager.discover_adapters()
        print(json.dumps(discovered, indent=2))
        return

    if args.adapters:
        for entry in _parse_adapters_arg(args.adapters):
            manager.add_adapter(entry["interface"], entry["role"])

    if args.setup:
        require_root()
        for interface, info in manager.adapters.items():
            if info["role"] in ("monitor", "scan"):
                manager.set_monitor_mode(interface)
            else:
                manager.set_managed_mode(interface)

    print(json.dumps(manager.get_status(), indent=2))


if __name__ == "__main__":
    main()
