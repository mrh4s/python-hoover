"""Tests for ap_scanner.py — WiFi AP Scanner."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing the module
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

from ap_scanner import APScanner  # noqa: E402

# Import the mocked scapy classes as the production code sees them
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp, RadioTap  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner(mock_interface):
    return APScanner(interface=mock_interface, timeout=10)


@pytest.fixture
def scanner_with_output(mock_interface, tmp_path):
    return APScanner(
        interface=mock_interface, timeout=10,
        output_file=str(tmp_path / "results.csv"),
    )


def _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", ssid="TestNet", channel=6,
                         signal=-50, has_privacy=True, has_rsn=True, rsn_info=b"\x01\x00"):
    """Create a mock beacon packet."""
    pkt = MagicMock()

    # haslayer uses identity comparison with mocked classes
    beacon_layers = {Dot11Beacon, RadioTap, Dot11}
    pkt.haslayer = lambda cls: cls in beacon_layers

    # Dot11 layer
    dot11_layer = MagicMock()
    dot11_layer.addr3 = bssid

    # Beacon layer
    beacon_layer = MagicMock()
    beacon_layer.cap = 0x0011 if has_privacy else 0x0001

    # RadioTap layer
    radiotap_layer = MagicMock()
    radiotap_layer.dBm_AntSignal = signal

    def getitem(self, cls):
        if cls is Dot11:
            return dot11_layer
        if cls is Dot11Beacon:
            return beacon_layer
        if cls is RadioTap:
            return radiotap_layer
        return dot11_layer
    pkt.__getitem__ = getitem

    # Build Dot11Elt chain
    ssid_elt = MagicMock()
    ssid_elt.ID = 0
    ssid_elt.info = ssid.encode()

    ds_elt = MagicMock()
    ds_elt.ID = 3
    ds_elt.info = bytes([channel])

    rsn_elt = MagicMock()
    rsn_elt.ID = 48 if has_rsn else 99
    rsn_elt.info = rsn_info

    end_elt = MagicMock()
    end_elt.ID = 255
    end_elt.info = b""
    end_elt.payload = MagicMock()
    end_elt.payload.getlayer = MagicMock(return_value=None)

    rsn_elt.payload = MagicMock()
    rsn_elt.payload.getlayer = MagicMock(return_value=end_elt)
    ds_elt.payload = MagicMock()
    ds_elt.payload.getlayer = MagicMock(return_value=rsn_elt)
    ssid_elt.payload = MagicMock()
    ssid_elt.payload.getlayer = MagicMock(return_value=ds_elt)

    pkt.getlayer = MagicMock(return_value=ssid_elt)

    return pkt


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAPScannerInit:
    def test_defaults(self, mock_interface):
        s = APScanner(interface=mock_interface)
        assert s.interface == mock_interface
        assert s.timeout == 30
        assert s.channel_hop is True
        assert s.access_points == {}
        assert s.bands == "2.4"

    def test_custom_params(self, mock_interface):
        s = APScanner(
            interface=mock_interface, timeout=60,
            channel_hop=False, fixed_channel=11,
            output_file="out.csv",
        )
        assert s.timeout == 60
        assert s.channel_hop is False
        assert s.fixed_channel == 11
        assert s.output_file == "out.csv"

    def test_custom_bands(self, mock_interface):
        s = APScanner(interface=mock_interface, bands="2.4,5")
        assert s.bands == "2.4,5"


class TestPacketHandler:
    def test_beacon_adds_ap(self, scanner):
        pkt = _make_beacon_packet()
        scanner.packet_handler(pkt)
        assert "AA:BB:CC:DD:EE:FF" in scanner.access_points
        ap = scanner.access_points["AA:BB:CC:DD:EE:FF"]
        assert ap["ssid"] == "TestNet"
        assert ap["beacon_count"] == 1

    def test_duplicate_beacon_increments_count(self, scanner):
        pkt = _make_beacon_packet()
        scanner.packet_handler(pkt)
        scanner.packet_handler(pkt)
        assert scanner.access_points["AA:BB:CC:DD:EE:FF"]["beacon_count"] == 2

    def test_hidden_ssid(self, scanner):
        pkt = _make_beacon_packet(ssid="")
        scanner.packet_handler(pkt)
        assert scanner.access_points["AA:BB:CC:DD:EE:FF"]["ssid"] == ""

    def test_non_beacon_ignored(self, scanner):
        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=False)
        scanner.packet_handler(pkt)
        assert len(scanner.access_points) == 0


class TestDetermineEncryption:
    def test_wpa2(self, scanner):
        pkt = _make_beacon_packet(has_privacy=True, has_rsn=True)
        scanner.packet_handler(pkt)
        ap = scanner.access_points["AA:BB:CC:DD:EE:FF"]
        assert ap["encryption"] == "WPA2"

    def test_open(self, scanner):
        pkt = _make_beacon_packet(has_privacy=False, has_rsn=False)
        scanner.packet_handler(pkt)
        ap = scanner.access_points["AA:BB:CC:DD:EE:FF"]
        assert ap["encryption"] == "Open"


def _make_rsn(*akm_types, pairwise=(4,), group=4):
    """Build RSN IE body bytes with the given AKM suite types."""
    rsn = b"\x01\x00"
    rsn += b"\x00\x0f\xac" + bytes([group])
    rsn += len(pairwise).to_bytes(2, "little")
    for p in pairwise:
        rsn += b"\x00\x0f\xac" + bytes([p])
    rsn += len(akm_types).to_bytes(2, "little")
    for a in akm_types:
        rsn += b"\x00\x0f\xac" + bytes([a])
    return rsn


class TestRSNEncryption:
    def _enc(self, scanner, *akms):
        pkt = _make_beacon_packet(rsn_info=_make_rsn(*akms))
        scanner.packet_handler(pkt)
        return scanner.access_points["AA:BB:CC:DD:EE:FF"]

    def test_wpa3_sae_detection(self, scanner):
        ap = self._enc(scanner, 8)
        assert ap["encryption"] == "WPA3"
        assert ap["akm_suites"] == ["SAE"]

    def test_wpa3_transition_mode(self, scanner):
        ap = self._enc(scanner, 2, 8)
        assert ap["encryption"] == "WPA3/WPA2"
        assert ap["akm_suites"] == ["PSK", "SAE"]

    def test_wpa2_enterprise_detection(self, scanner):
        ap = self._enc(scanner, 1)
        assert ap["encryption"] == "WPA2-Enterprise"

    def test_owe_detection(self, scanner):
        ap = self._enc(scanner, 18)
        assert ap["encryption"] == "OWE"

    def test_wpa2_psk_detection_unchanged(self, scanner):
        ap = self._enc(scanner, 2)
        assert ap["encryption"] == "WPA2"
        assert ap["akm_suites"] == ["PSK"]

    def test_wpa3_enterprise_192bit(self, scanner):
        ap = self._enc(scanner, 11)
        assert ap["encryption"] == "WPA3-Enterprise"

    def test_rsn_ie_parsing(self, scanner):
        result = scanner._parse_rsn_ie(_make_rsn(2, 8, pairwise=(4, 2), group=4))
        assert result == {
            "akm_suites": ["PSK", "SAE"],
            "pairwise_ciphers": ["CCMP", "TKIP"],
            "group_cipher": "CCMP",
        }

    def test_rsn_ie_parsing_truncated(self, scanner):
        result = scanner._parse_rsn_ie(b"\x01\x00")
        assert result["akm_suites"] == []


class TestSaveResults:
    def test_save_csv(self, tmp_path, mock_interface):
        output = str(tmp_path / "results.csv")
        s = APScanner(interface=mock_interface, output_file=output)
        s.access_points = {
            "AA:BB:CC:DD:EE:FF": {
                "ssid": "TestNet", "channel": 6, "signal": -50,
                "encryption": "WPA2", "vendor": "TestVendor",
                "beacon_count": 10, "first_seen": "2024-01-01 00:00:00",
                "last_seen": "2024-01-01 00:01:00",
            },
        }
        s.save_results()
        assert os.path.exists(output)
        with open(output) as f:
            content = f.read()
        assert "AA:BB:CC:DD:EE:FF" in content
        assert "TestNet" in content

    def test_save_json(self, tmp_path, mock_interface):
        output = str(tmp_path / "results.json")
        s = APScanner(interface=mock_interface, output_file=output)
        s.access_points = {
            "AA:BB:CC:DD:EE:FF": {
                "ssid": "TestNet", "channel": 6, "signal": -50,
                "encryption": "WPA2", "vendor": "TestVendor",
                "beacon_count": 10, "first_seen": "2024-01-01 00:00:00",
                "last_seen": "2024-01-01 00:01:00",
            },
        }
        s.save_results()
        assert os.path.exists(output)
        data = json.loads(open(output).read())
        assert "AA:BB:CC:DD:EE:FF" in data

    def test_save_no_file(self, scanner):
        scanner.output_file = None
        scanner.save_results()

    def test_save_empty_results(self, scanner_with_output):
        scanner_with_output.save_results()


class TestChannelHop:
    @patch("ap_scanner.subprocess.run")
    @patch("ap_scanner.time.sleep", side_effect=StopIteration)
    def test_hop_loop(self, mock_sleep, mock_run, scanner):
        scanner._hop_running = True
        with pytest.raises(StopIteration):
            scanner._channel_hop_loop()
        mock_run.assert_called_once()

    @patch("ap_scanner.subprocess.run")
    def test_set_channel(self, mock_run, scanner):
        scanner._set_channel(11)
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "11" in args

    @patch("ap_scanner.subprocess.run")
    @patch("ap_scanner.time.sleep", side_effect=StopIteration)
    def test_hop_loop_5ghz_band(self, mock_sleep, mock_run, mock_interface):
        s = APScanner(interface=mock_interface, bands="5")
        s._hop_running = True
        with pytest.raises(StopIteration):
            s._channel_hop_loop()
        args = mock_run.call_args[0][0]
        assert "36" in args


class TestStart:
    @patch("ap_scanner.sniff")
    def test_start_returns_aps(self, mock_sniff, scanner):
        mock_sniff.return_value = None
        result = scanner.start()
        assert isinstance(result, dict)
        mock_sniff.assert_called_once()

    @patch("ap_scanner.sniff")
    def test_start_with_fixed_channel(self, mock_sniff, mock_interface):
        s = APScanner(interface=mock_interface, fixed_channel=6)
        with patch.object(s, "_set_channel") as mock_set:
            s.start()
            mock_set.assert_called_once_with(6)


class TestPrintResults:
    def test_print_no_results(self, scanner):
        scanner.print_results()
        # Logger output goes to logger, not stdout

    def test_print_with_results(self, scanner, capsys):
        scanner.access_points = {
            "AA:BB:CC:DD:EE:FF": {
                "ssid": "TestNet", "channel": 6, "signal": -50,
                "encryption": "WPA2", "vendor": "TestVendor",
                "beacon_count": 10, "first_seen": "2024-01-01",
                "last_seen": "2024-01-01",
            },
        }
        scanner.print_results()
        captured = capsys.readouterr()
        assert "TestNet" in captured.out
        assert "AA:BB:CC:DD:EE:FF" in captured.out
