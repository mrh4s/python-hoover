"""Tests for ap_scanner.py hidden SSID reveal functionality (Feature 6)."""

import sys
from unittest.mock import MagicMock, patch

# Mock scapy before importing the module
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.layers.eap", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.utils", MagicMock())
sys.modules.setdefault("scapy.packet", MagicMock())

# Import the mocked scapy classes as the production code sees them
from scapy.layers.dot11 import (  # noqa: E402
    Dot11,
    Dot11AssoReq,
    Dot11Beacon,
    Dot11ProbeResp,
    Dot11ReassoReq,
    RadioTap,
)

from ap_scanner import APScanner, main  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", ssid="TestNet", channel=6,
                         signal=-50, has_privacy=False):
    """Create a mock beacon packet (mirrors tests/test_ap_scanner.py helper)."""
    pkt = MagicMock()

    beacon_layers = {Dot11Beacon, RadioTap, Dot11}
    pkt.haslayer = lambda cls: cls in beacon_layers

    dot11_layer = MagicMock()
    dot11_layer.addr3 = bssid

    beacon_layer = MagicMock()
    beacon_layer.cap = 0x0011 if has_privacy else 0x0001

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

    ssid_elt = MagicMock()
    ssid_elt.ID = 0
    ssid_elt.info = ssid.encode() if isinstance(ssid, str) else ssid

    ds_elt = MagicMock()
    ds_elt.ID = 3
    ds_elt.info = bytes([channel])
    ds_elt.payload = MagicMock()
    ds_elt.payload.getlayer = MagicMock(return_value=None)

    ssid_elt.payload = MagicMock()
    ssid_elt.payload.getlayer = MagicMock(return_value=ds_elt)

    pkt.getlayer = MagicMock(return_value=ssid_elt)

    return pkt


def _make_probe_resp_packet(bssid="AA:BB:CC:DD:EE:FF", ssid="RevealedNet"):
    """Create a mock Dot11ProbeResp packet carrying a real SSID."""
    pkt = MagicMock()

    layers = {Dot11ProbeResp, Dot11}
    pkt.haslayer = lambda cls: cls in layers

    dot11_layer = MagicMock()
    dot11_layer.addr3 = bssid

    def getitem(self, cls):
        if cls is Dot11:
            return dot11_layer
        return dot11_layer
    pkt.__getitem__ = getitem

    ssid_elt = MagicMock()
    ssid_elt.ID = 0
    ssid_elt.info = ssid.encode()
    ssid_elt.payload = MagicMock()
    ssid_elt.payload.getlayer = MagicMock(return_value=None)

    pkt.getlayer = MagicMock(return_value=ssid_elt)

    return pkt


def _make_assoc_packet(bssid="AA:BB:CC:DD:EE:FF", ssid="ClientRevealedNet", reassoc=False):
    """Create a mock Dot11AssoReq / Dot11ReassoReq packet carrying the SSID."""
    pkt = MagicMock()

    target_layer = Dot11ReassoReq if reassoc else Dot11AssoReq
    layers = {target_layer, Dot11}
    pkt.haslayer = lambda cls: cls in layers

    dot11_layer = MagicMock()
    dot11_layer.addr1 = bssid  # client -> AP, addr1 is the BSSID

    def getitem(self, cls):
        if cls is Dot11:
            return dot11_layer
        return dot11_layer
    pkt.__getitem__ = getitem

    ssid_elt = MagicMock()
    ssid_elt.ID = 0
    ssid_elt.info = ssid.encode()
    ssid_elt.payload = MagicMock()
    ssid_elt.payload.getlayer = MagicMock(return_value=None)

    pkt.getlayer = MagicMock(return_value=ssid_elt)

    return pkt


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestIsHiddenSsid:
    def test_is_hidden_ssid_empty_string(self):
        assert APScanner._is_hidden_ssid("") is True

    def test_is_hidden_ssid_null_bytes(self):
        assert APScanner._is_hidden_ssid("\x00\x00\x00") is True

    def test_is_hidden_ssid_real_ssid(self):
        assert APScanner._is_hidden_ssid("HomeWiFi") is False


class TestHiddenApDetection:
    def test_hidden_ap_detected_during_scan(self, mock_interface):
        scanner = APScanner(interface=mock_interface, timeout=10)
        pkt = _make_beacon_packet(ssid="")
        scanner.packet_handler(pkt)

        assert "AA:BB:CC:DD:EE:FF" in scanner.hidden_aps
        assert scanner.access_points["AA:BB:CC:DD:EE:FF"]["ssid"] == ""


class TestSendDirectedProbe:
    @patch("ap_scanner.sendp")
    def test_send_directed_probe_frame_structure(self, mock_sendp, mock_interface):
        scanner = APScanner(interface=mock_interface, timeout=10)
        with patch.object(scanner, "_set_channel") as mock_set_channel:
            scanner._send_directed_probe("AA:BB:CC:DD:EE:FF", 6)

        mock_set_channel.assert_called_once_with(6)
        mock_sendp.assert_called_once()
        call_kwargs = mock_sendp.call_args.kwargs
        assert call_kwargs.get("iface") == mock_interface


class TestProbeResponseHandler:
    def test_probe_response_reveals_ssid(self, mock_interface):
        scanner = APScanner(interface=mock_interface, timeout=10)
        scanner.hidden_aps["AA:BB:CC:DD:EE:FF"] = {"channel": 6, "revealed": False}
        scanner.access_points["AA:BB:CC:DD:EE:FF"] = {"ssid": "", "channel": 6}

        pkt = _make_probe_resp_packet(ssid="RevealedNet")
        scanner._probe_response_handler(pkt)

        assert scanner.revealed_ssids["AA:BB:CC:DD:EE:FF"] == "RevealedNet"
        assert scanner.hidden_aps["AA:BB:CC:DD:EE:FF"]["revealed"] is True


class TestAssociationRequestReveal:
    def test_association_request_reveals_ssid(self, mock_interface):
        scanner = APScanner(interface=mock_interface, timeout=10)
        scanner.hidden_aps["AA:BB:CC:DD:EE:FF"] = {"channel": 6, "revealed": False}
        scanner.access_points["AA:BB:CC:DD:EE:FF"] = {"ssid": "", "channel": 6}

        pkt = _make_assoc_packet(ssid="ClientRevealedNet")
        scanner.packet_handler(pkt)

        assert scanner.revealed_ssids["AA:BB:CC:DD:EE:FF"] == "ClientRevealedNet"
        assert scanner.access_points["AA:BB:CC:DD:EE:FF"]["ssid"] == "ClientRevealedNet"
        assert scanner.hidden_aps["AA:BB:CC:DD:EE:FF"]["revealed"] is True

    def test_reassociation_request_reveals_ssid(self, mock_interface):
        scanner = APScanner(interface=mock_interface, timeout=10)
        pkt = _make_assoc_packet(ssid="ReassocNet", reassoc=True)
        scanner.packet_handler(pkt)

        assert scanner.revealed_ssids["AA:BB:CC:DD:EE:FF"] == "ReassocNet"


class TestRevealMerge:
    @patch("ap_scanner.sniff")
    @patch("ap_scanner.sendp")
    def test_reveal_merges_into_access_points(self, mock_sendp, mock_sniff, mock_interface):
        scanner = APScanner(interface=mock_interface, timeout=10)
        scanner.hidden_aps["AA:BB:CC:DD:EE:FF"] = {"channel": 6, "revealed": False}
        scanner.access_points["AA:BB:CC:DD:EE:FF"] = {"ssid": "", "channel": 6}

        def fake_sniff(iface, prn, timeout, store):
            scanner.revealed_ssids["AA:BB:CC:DD:EE:FF"] = "NowKnownNet"

        mock_sniff.side_effect = fake_sniff

        with patch.object(scanner, "_set_channel"):
            result = scanner.reveal_hidden_ssids(timeout=5)

        assert result["AA:BB:CC:DD:EE:FF"] == "NowKnownNet"
        assert scanner.access_points["AA:BB:CC:DD:EE:FF"]["ssid"] == "NowKnownNet"


class TestCliRevealHiddenFlag:
    @patch("ap_scanner.APScanner.save_results")
    @patch("ap_scanner.APScanner.print_results")
    @patch("ap_scanner.APScanner.start")
    @patch("ap_scanner.require_root")
    @patch("ap_scanner.check_monitor_mode", return_value=True)
    @patch("sys.argv", ["ap_scanner.py", "-i", "wlan0mon", "--reveal-hidden"])
    def test_cli_reveal_hidden_flag(self, mock_check_mon, mock_require_root,
                                     mock_start, mock_print, mock_save):
        captured = {}
        original_init = APScanner.__init__

        def capturing_init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            captured["scanner"] = self

        with patch.object(APScanner, "__init__", capturing_init):
            with patch.object(APScanner, "reveal_hidden_ssids"):
                main()

        scanner = captured["scanner"]
        assert scanner.reveal_hidden is True
        assert scanner.deauth_reveal is False


class TestNoActiveProbingWithoutFlag:
    @patch("ap_scanner.APScanner.save_results")
    @patch("ap_scanner.APScanner.print_results")
    @patch("ap_scanner.APScanner.reveal_hidden_ssids")
    @patch("ap_scanner.APScanner.start")
    @patch("ap_scanner.require_root")
    @patch("ap_scanner.check_monitor_mode", return_value=True)
    @patch("sys.argv", ["ap_scanner.py", "-i", "wlan0mon"])
    def test_no_active_probing_without_flag(self, mock_check_mon, mock_require_root,
                                             mock_start, mock_reveal, mock_print, mock_save):
        main()
        mock_reveal.assert_not_called()
