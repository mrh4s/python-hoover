"""Tests for oui_lookup.py — MAC vendor lookup."""

import pytest

from oui_lookup import lookup_vendor, OUI_DATABASE


class TestLookupVendor:
    """Tests for lookup_vendor()."""

    @pytest.mark.parametrize(
        "mac, expected_vendor",
        [
            ("00:1B:63:AA:BB:CC", "Apple"),
            ("00:1B:21:11:22:33", "Intel"),
            ("00:07:AB:11:22:33", "Samsung"),
            ("08:9E:08:11:22:33", "Google"),
            ("00:0D:3A:11:22:33", "Microsoft"),
            ("00:00:0C:11:22:33", "Cisco"),
            ("B8:27:EB:11:22:33", "Raspberry Pi"),
        ],
    )
    def test_lookup_known_vendor(self, mac, expected_vendor):
        assert lookup_vendor(mac) == expected_vendor

    def test_lookup_unknown_vendor(self):
        # Use a prefix that is very unlikely to be in the database
        assert lookup_vendor("00:00:01:AA:BB:CC") == "Unknown"

    @pytest.mark.parametrize(
        "mac",
        [
            # Locally administered bit set (second hex digit is 2, 3, 6, 7, A, B, E, F)
            "02:00:00:00:00:01",
            "06:11:22:33:44:55",
            "0A:00:00:00:00:00",
            "0E:AB:CD:EF:01:23",
            "12:34:56:78:9A:BC",
            "DA:BB:CC:DD:EE:FF",
        ],
    )
    def test_lookup_randomized_mac(self, mac):
        result = lookup_vendor(mac)
        assert result == "Randomized"

    @pytest.mark.parametrize(
        "mac",
        [
            "00:1b:63:aa:bb:cc",   # all lowercase
            "00:1B:63:AA:BB:CC",   # all uppercase
            "00:1b:63:AA:bb:CC",   # mixed case
        ],
    )
    def test_lookup_case_insensitive(self, mac):
        """All case variants of an Apple OUI should return 'Apple'."""
        assert lookup_vendor(mac) == "Apple"

    @pytest.mark.parametrize(
        "bad_input",
        [
            "",
            None,
            12345,
            "not-a-mac",
            "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ",
            "00:1B",
        ],
    )
    def test_lookup_invalid_mac(self, bad_input):
        assert lookup_vendor(bad_input) == "Unknown"

    def test_dash_separated_mac(self):
        """Dash-separated MACs should also resolve the vendor."""
        result = lookup_vendor("00-1B-63-AA-BB-CC")
        assert result == "Apple"

    def test_oui_database_has_entries(self):
        """Sanity-check that the embedded OUI database is not empty."""
        assert len(OUI_DATABASE) > 100
