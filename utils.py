#!/usr/bin/env python3
"""Shared utilities for Hoover WiFi Security Toolkit"""

import os
import sys
import re
import subprocess
import logging


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
    with open(filepath, 'r', encoding='utf-8') as f:
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
