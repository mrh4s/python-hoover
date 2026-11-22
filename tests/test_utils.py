"""Tests for utils.py — shared utilities."""

import logging
import os
import sys
from unittest.mock import patch

import pytest

from utils import (
    validate_mac,
    validate_interface,
    check_monitor_mode,
    load_ssids,
    require_root,
    setup_logging,
    get_channels,
    CHANNELS_2GHZ,
    CHANNELS_5GHZ,
    CHANNELS_6GHZ,
)


# ---------------------------------------------------------------------------
# validate_mac
# ---------------------------------------------------------------------------

class TestValidateMac:
    """Tests for validate_mac()."""

    @pytest.mark.parametrize(
        "mac",
        [
            "00:1B:63:AA:BB:CC",   # uppercase
            "00:1b:63:aa:bb:cc",   # lowercase
            "aA:bB:cC:dD:eE:fF",  # mixed case
            "FF:FF:FF:FF:FF:FF",   # broadcast
            "00:00:00:00:00:00",   # all zeros
        ],
    )
    def test_validate_mac_valid(self, mac):
        assert validate_mac(mac) is True

    @pytest.mark.parametrize(
        "mac",
        [
            "00:1B:63",                # too short
            "00:1B:63:AA:BB",          # five octets
            "00-1B-63-AA-BB-CC",       # dash separators
            "001B63AABBCC",            # no separators
            "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",      # non-hex
            "GG:HH:II:JJ:KK:LL",      # non-hex letters
            "",                        # empty string
            "   ",                     # whitespace only
            "00:1B:63:AA:BB:CC:DD",    # too many octets
        ],
    )
    def test_validate_mac_invalid(self, mac):
        assert validate_mac(mac) is False

    def test_validate_mac_none(self):
        assert validate_mac(None) is False

    def test_validate_mac_non_string(self):
        assert validate_mac(12345) is False


# ---------------------------------------------------------------------------
# validate_interface
# ---------------------------------------------------------------------------

class TestValidateInterface:
    """Tests for validate_interface()."""

    @pytest.mark.parametrize(
        "iface",
        [
            "wlan0",
            "wlan0mon",
            "eth0",
            "wlan-1",
            "wlan_1",
            "lo",
            "enp3s0",
        ],
    )
    def test_validate_interface_valid(self, iface):
        assert validate_interface(iface) is True

    @pytest.mark.parametrize(
        "iface",
        [
            "; rm -rf /",
            "wlan0; ls",
            "../etc",
            "",
            "   ",
            "wlan 0",             # contains space
            "wlan0\nls",          # newline injection
            "/dev/null",          # path separator
            "wlan$0",             # special char
        ],
    )
    def test_validate_interface_invalid(self, iface):
        assert validate_interface(iface) is False

    def test_validate_interface_none(self):
        assert validate_interface(None) is False

    def test_validate_interface_non_string(self):
        assert validate_interface(123) is False


# ---------------------------------------------------------------------------
# check_monitor_mode
# ---------------------------------------------------------------------------

class TestCheckMonitorMode:
    """Tests for check_monitor_mode()."""

    @patch("utils.subprocess.run")
    def test_monitor_mode_detected(self, mock_run):
        mock_run.return_value.stdout = "wlan0mon  IEEE 802.11  Mode:Monitor  Frequency:2.437 GHz"
        assert check_monitor_mode("wlan0mon") is True

    @patch("utils.subprocess.run")
    def test_managed_mode(self, mock_run):
        mock_run.return_value.stdout = "wlan0  IEEE 802.11  Mode:Managed"
        assert check_monitor_mode("wlan0") is False

    def test_invalid_interface_name(self):
        # Should return False without calling subprocess
        assert check_monitor_mode("; rm -rf /") is False


# ---------------------------------------------------------------------------
# load_ssids
# ---------------------------------------------------------------------------

class TestLoadSsids:
    """Tests for load_ssids()."""

    def test_load_ssids(self, sample_ssid_file):
        result = load_ssids(sample_ssid_file)
        assert result == ["CoffeeShop-WiFi", "Hotel-Guest", "Airport-Free-WiFi"]

    def test_load_ssids_empty(self, empty_ssid_file):
        result = load_ssids(empty_ssid_file)
        assert result == []

    def test_load_ssids_comments_only(self, comments_only_ssid_file):
        result = load_ssids(comments_only_ssid_file)
        assert result == []

    def test_load_ssids_missing(self, tmp_dir):
        with pytest.raises(FileNotFoundError):
            load_ssids(str(tmp_dir / "nonexistent.txt"))


# ---------------------------------------------------------------------------
# require_root
# ---------------------------------------------------------------------------

class TestRequireRoot:
    """Tests for require_root()."""

    @patch("utils.os.geteuid", return_value=1000)
    def test_require_root_as_nonroot(self, _mock_geteuid):
        with pytest.raises(SystemExit) as exc_info:
            require_root()
        assert exc_info.value.code == 1

    @patch("utils.os.geteuid", return_value=0)
    def test_require_root_as_root(self, _mock_geteuid):
        # Should not raise
        require_root()


# ---------------------------------------------------------------------------
# get_channels
# ---------------------------------------------------------------------------

class TestGetChannels:
    """Tests for get_channels()."""

    def test_get_channels_2ghz(self):
        result = get_channels("2.4")
        assert result == list(range(1, 14))

    def test_get_channels_5ghz(self):
        result = get_channels("5")
        assert result == CHANNELS_5GHZ
        assert result[0] == 36

    def test_get_channels_6ghz(self):
        result = get_channels("6")
        assert result == CHANNELS_6GHZ
        assert result[0] == 1

    def test_get_channels_all(self):
        result = get_channels("all")
        assert result == CHANNELS_2GHZ + CHANNELS_5GHZ + CHANNELS_6GHZ

    def test_get_channels_default(self):
        result = get_channels()
        assert result == list(range(1, 14))

    def test_get_channels_combined(self):
        result = get_channels("2.4,5")
        assert result == CHANNELS_2GHZ + CHANNELS_5GHZ

    def test_get_channels_combined_all_three(self):
        result = get_channels("2.4,5,6")
        assert result == CHANNELS_2GHZ + CHANNELS_5GHZ + CHANNELS_6GHZ

    def test_get_channels_whitespace(self):
        result = get_channels(" 2.4 , 5 ")
        assert result == CHANNELS_2GHZ + CHANNELS_5GHZ

    def test_get_channels_no_duplicates(self):
        result = get_channels("2.4,2.4")
        assert result == CHANNELS_2GHZ

    def test_get_channels_invalid_band(self):
        with pytest.raises(ValueError):
            get_channels("2.4,bogus")

    def test_get_channels_empty_string(self):
        with pytest.raises(ValueError):
            get_channels("")


# ---------------------------------------------------------------------------
# setup_logging
# ---------------------------------------------------------------------------

class TestSetupLogging:
    """Tests for setup_logging()."""

    def test_setup_logging_returns_logger(self):
        logger = setup_logging("test_logger_default")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test_logger_default"

    def test_setup_logging_info_level(self):
        logger = setup_logging("test_logger_info", verbose=False)
        assert logger.level == logging.INFO

    def test_setup_logging_debug_level(self):
        logger = setup_logging("test_logger_debug", verbose=True)
        assert logger.level == logging.DEBUG

    def test_setup_logging_has_handler(self):
        logger = setup_logging("test_logger_handler")
        assert len(logger.handlers) >= 1
