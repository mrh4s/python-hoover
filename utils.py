#!/usr/bin/env python3
"""Shared utilities for Hoover WiFi Security Toolkit"""

import logging
import os
import re
import subprocess
import sys

CHANNELS_2GHZ: list[int] = list(range(1, 14))
CHANNELS_5GHZ: list[int] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165,
]
CHANNELS_6GHZ: list[int] = [
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73,
    77, 81, 85, 89, 93,
]

_BAND_CHANNELS: dict[str, list[int]] = {
    "2.4": CHANNELS_2GHZ,
    "5": CHANNELS_5GHZ,
    "6": CHANNELS_6GHZ,
}


def get_channels(bands: str = "2.4") -> list[int]:
    """Return the channel list for the given bands.

    Args:
        bands: Comma-separated string of bands, e.g. "2.4", "2.4,5",
            "2.4,5,6", "5", or "all" (shorthand for every supported band).

    Returns:
        A list of channel numbers covering the requested bands, in band
        order (2.4 GHz, then 5 GHz, then 6 GHz), with duplicates removed.

    Raises:
        ValueError: If an unrecognized band is given.
    """
    if not bands or not isinstance(bands, str):
        raise ValueError(f"Invalid bands value: {bands!r}")

    bands = bands.strip().lower()
    if bands == "all":
        requested = ["2.4", "5", "6"]
    else:
        requested = [b.strip() for b in bands.split(",") if b.strip()]

    if not requested:
        raise ValueError(f"Invalid bands value: {bands!r}")

    channels: list[int] = []
    seen_bands: set[str] = set()
    for band in requested:
        if band not in _BAND_CHANNELS:
            raise ValueError(
                f"Unknown band: {band!r} (expected one of 2.4, 5, 6, or all)"
            )
        if band in seen_bands:
            # Avoid duplicating an entire band's channel list if it was
            # requested more than once (channel numbers can legitimately
            # repeat across different bands, e.g. 1 in both 2.4 and 6 GHz).
            continue
        seen_bands.add(band)
        channels.extend(_BAND_CHANNELS[band])

    return channels


def validate_ip(ip: str) -> bool:
    """Validate IPv4 address format.

    Args:
        ip: IPv4 address string to validate.

    Returns:
        True if the IP address is valid, False otherwise.
    """
    if not ip or not isinstance(ip, str):
        return False
    pattern = re.compile(
        r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$'
    )
    return bool(pattern.match(ip))


def validate_mac(mac: str) -> bool:
    """Validate MAC address format (XX:XX:XX:XX:XX:XX).

    Args:
        mac: MAC address string to validate.

    Returns:
        True if the MAC address is valid, False otherwise.
    """
    if not mac or not isinstance(mac, str):
        return False
    pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
    return bool(pattern.match(mac))


def validate_interface(interface: str) -> bool:
    """Validate network interface name (alphanumeric, hyphens, underscores only).

    Args:
        interface: Network interface name to validate.

    Returns:
        True if the interface name is valid, False otherwise.
    """
    if not interface or not isinstance(interface, str):
        return False
    return bool(re.match(r'^[A-Za-z0-9_-]+$', interface))


def check_monitor_mode(interface: str) -> bool:
    """Check if wireless interface is in monitor mode.

    Args:
        interface: Network interface name to check.

    Returns:
        True if the interface is in monitor mode, False otherwise.
    """
    if not validate_interface(interface):
        return False
    try:
        result = subprocess.run(
            ['iwconfig', interface],
            capture_output=True,
            text=True,
            timeout=5
        )
        return 'Mode:Monitor' in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def load_ssids(filepath: str) -> list[str]:
    """Load SSIDs from text file, skipping comments and blank lines.

    Args:
        filepath: Path to the text file containing SSIDs.

    Returns:
        List of SSID strings.

    Raises:
        FileNotFoundError: If the file does not exist.
        IOError: If the file cannot be read.
    """
    with open(filepath, encoding='utf-8') as f:
        return [
            line.strip() for line in f
            if line.strip() and not line.startswith('#')
        ]


def require_root() -> None:
    """Exit with error if not running as root."""
    if os.geteuid() != 0:
        logging.error("This script must be run as root (use sudo)")
        sys.exit(1)


def setup_logging(name: str, verbose: bool = False) -> logging.Logger:
    """Configure and return a logger with consistent formatting.

    Args:
        name: Logger name (typically the module name).
        verbose: If True, set log level to DEBUG; otherwise INFO.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        level = logging.DEBUG if verbose else logging.INFO
        handler.setLevel(level)
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(level)
    return logger
