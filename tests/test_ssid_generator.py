"""Tests for ssid_generator.py — SSIDGenerator (scapy mocked)."""

import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock scapy before importing ssid_generator
# ---------------------------------------------------------------------------
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

from ssid_generator import SSIDGenerator  # noqa: E402

# ---------------------------------------------------------------------------
# generate_mac
# ---------------------------------------------------------------------------


class TestGenerateMAC:
    """Tests for SSIDGenerator.generate_mac."""

    def test_generate_mac_format(self):
        gen = SSIDGenerator(interface=None, ssid_file="dummy.txt")
        mac = gen.generate_mac(0)
        # Should be XX:XX:XX:XX:XX:XX format
        parts = mac.split(":")
        assert len(parts) == 6
        for part in parts:
            assert len(part) == 2
            int(part, 16)  # should not raise

    def test_generate_mac_unique_per_index(self):
        gen = SSIDGenerator(interface=None, ssid_file="dummy.txt")
        macs = {gen.generate_mac(i) for i in range(50)}
        assert len(macs) == 50

    def test_generate_mac_locally_administered(self):
        """First byte must have the locally administered bit (0x02) set."""
        gen = SSIDGenerator(interface=None, ssid_file="dummy.txt")
        for idx in range(20):
            mac = gen.generate_mac(idx)
            first_octet = int(mac.split(":")[0], 16)
            assert first_octet & 0x02, f"MAC {mac} does not have locally administered bit set"

    def test_generate_mac_deterministic(self):
        gen = SSIDGenerator(interface=None, ssid_file="dummy.txt")
        assert gen.generate_mac(5) == gen.generate_mac(5)


# ---------------------------------------------------------------------------
# create_beacon
# ---------------------------------------------------------------------------


class TestCreateBeacon:
    """Tests for SSIDGenerator.create_beacon (scapy mocked)."""

    def test_create_beacon_returns_frame(self):
        """create_beacon should return a composed scapy frame object."""
        gen = SSIDGenerator(interface=None, ssid_file="dummy.txt")
        frame = gen.create_beacon("TestSSID", "02:00:00:00:00:01")
        # With mocked scapy the frame is a MagicMock built by the `/` operator
        assert frame is not None

    def test_create_beacon_uses_correct_ssid(self):
        """The SSID should be passed through to Dot11Elt."""
        gen = SSIDGenerator(interface=None, ssid_file="dummy.txt")
        with patch("ssid_generator.Dot11Elt") as mock_elt:
            mock_elt.return_value = MagicMock()
            gen.create_beacon("MyNetwork", "02:00:00:00:00:01")
            # First positional call to Dot11Elt should have ID='SSID' and info='MyNetwork'
            calls = mock_elt.call_args_list
            ssid_call = calls[0]
            assert (
                ssid_call.kwargs.get("info") == "MyNetwork"
                or (len(ssid_call.args) > 0 and ssid_call.args[0] == "MyNetwork")
                or ssid_call[1].get("info") == "MyNetwork"
            )


# ---------------------------------------------------------------------------
# load_ssids integration
# ---------------------------------------------------------------------------


class TestLoadSSIDsIntegration:
    """Test that SSIDGenerator correctly loads SSIDs via the shared utility."""

    def test_load_ssids_integration(self, sample_ssid_file):
        gen = SSIDGenerator(interface=None, ssid_file=sample_ssid_file)
        result = gen.load_ssids_from_file()
        assert result is True
        assert gen.ssids == ["CoffeeShop-WiFi", "Hotel-Guest", "Airport-Free-WiFi"]
