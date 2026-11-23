"""Tests for wep_attack.py — WEP Attack module."""

import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.utils", MagicMock())
sys.modules.setdefault("scapy.packet", MagicMock())

# Import mocked classes as production code sees them
from scapy.layers.dot11 import Dot11, Dot11WEP  # noqa: E402

from wep_attack import ATTACK_MODES, WEPAttack, main  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def attack(mock_interface, tmp_path):
    return WEPAttack(
        interface=mock_interface,
        target_bssid="AA:BB:CC:DD:EE:FF",
        channel=6,
        output_dir=str(tmp_path / "captures"),
        timeout=300,
        target_ivs=1000,
    )


def _make_wep_packet(iv=b"\x01\x02\x03", keyid=0, has_wep=True,
                      has_dot11=True, fc_field=0x40, frame_len=68):
    """Create a mock packet with an optional Dot11WEP layer."""
    pkt = MagicMock()

    wep_layer = MagicMock()
    wep_layer.iv = iv
    wep_layer.keyid = keyid

    dot11_layer = MagicMock()
    dot11_layer.FCfield = fc_field

    layers_present = set()
    if has_wep:
        layers_present.add(Dot11WEP)
    if has_dot11:
        layers_present.add(Dot11)

    pkt.haslayer = lambda cls: cls in layers_present

    def getitem(self, cls):
        if cls is Dot11WEP:
            return wep_layer
        if cls is Dot11:
            return dot11_layer
        return MagicMock()
    pkt.__getitem__ = getitem

    pkt.__len__ = lambda self: frame_len

    return pkt


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_defaults(self, mock_interface):
        wep = WEPAttack(interface=mock_interface, target_bssid="AA:BB:CC:DD:EE:FF")
        assert wep.interface == mock_interface
        assert wep.target_bssid == "AA:BB:CC:DD:EE:FF"
        assert wep.channel is None
        assert wep.attack_mode == "arp-replay"
        assert wep.output_dir == "captures"
        assert wep.timeout == 600
        assert wep.target_ivs == 50000
        assert wep.iv_count == 0
        assert wep.unique_ivs == set()
        assert wep._running is False


class TestExtractIV:
    def test_extract_iv_from_wep_frame(self, attack):
        pkt = _make_wep_packet(iv=b"\x11\x22\x33", keyid=2, has_wep=True)
        result = attack._extract_iv(pkt)
        assert result == b"\x11\x22\x33\x02"

    def test_extract_iv_from_non_wep(self, attack):
        pkt = _make_wep_packet(has_wep=False)
        result = attack._extract_iv(pkt)
        assert result is None


class TestDetectArpRequest:
    def test_detect_arp_request_by_size(self, attack):
        pkt = _make_wep_packet(fc_field=0x40, frame_len=68)
        result = attack._detect_arp_request(pkt)
        assert result is True

    def test_detect_arp_request_wrong_size(self, attack):
        pkt = _make_wep_packet(fc_field=0x40, frame_len=200)
        result = attack._detect_arp_request(pkt)
        assert result is False


class TestFakeAuth:
    @patch("wep_attack.sendp")
    def test_fake_auth_frame_structure(self, mock_sendp, attack):
        with patch("wep_attack.validate_mac", return_value=True):
            result = attack._fake_auth("11:22:33:44:55:66")

        assert result is True
        assert mock_sendp.call_count == 2

        # First call: Dot11Auth frame addressed to/from the right MACs
        first_call_args = mock_sendp.call_args_list[0]
        assert first_call_args[1]["iface"] == attack.interface

        # The frame is built via scapy's `/` operator on MagicMocks, so we
        # can't inspect real fields, but we can verify Dot11 was
        # instantiated with the expected addressing and that Dot11Auth
        # was used with algo=0 (Open System), seqnum=1.
        import wep_attack as wep_module
        dot11_calls = wep_module.Dot11.call_args_list
        assert any(
            call.kwargs.get("addr1") == attack.target_bssid
            and call.kwargs.get("addr2") == "11:22:33:44:55:66"
            for call in dot11_calls
        )
        auth_calls = wep_module.Dot11Auth.call_args_list
        assert any(
            call.kwargs.get("algo") == 0 and call.kwargs.get("seqnum") == 1
            for call in auth_calls
        )

    def test_fake_auth_invalid_mac(self, attack):
        with patch("wep_attack.validate_mac", return_value=False):
            result = attack._fake_auth("not-a-mac")
        assert result is False


class TestPacketHandler:
    def test_packet_handler_counts_ivs(self, attack):
        pkt1 = _make_wep_packet(iv=b"\x01\x02\x03", frame_len=100, fc_field=0)
        pkt2 = _make_wep_packet(iv=b"\x04\x05\x06", frame_len=100, fc_field=0)

        attack.packet_handler(pkt1)
        attack.packet_handler(pkt2)

        assert attack.iv_count == 2

    def test_packet_handler_tracks_unique_ivs(self, attack):
        pkt1 = _make_wep_packet(iv=b"\x01\x02\x03", keyid=0, frame_len=100, fc_field=0)
        pkt2 = _make_wep_packet(iv=b"\x01\x02\x03", keyid=0, frame_len=100, fc_field=0)
        pkt3 = _make_wep_packet(iv=b"\x07\x08\x09", keyid=0, frame_len=100, fc_field=0)

        attack.packet_handler(pkt1)
        attack.packet_handler(pkt2)
        attack.packet_handler(pkt3)

        assert attack.iv_count == 3
        assert len(attack.unique_ivs) == 2


class TestSaveCapture:
    @patch("wep_attack.wrpcap")
    def test_save_capture_creates_pcap(self, mock_wrpcap, attack):
        pkt = _make_wep_packet()
        attack.captured_packets.append(pkt)

        result = attack.save_capture()

        assert result is not None
        assert result.endswith(".pcap")
        assert os.path.dirname(result) == attack.output_dir
        mock_wrpcap.assert_called_once()

    def test_save_capture_no_packets_returns_none(self, attack):
        result = attack.save_capture()
        assert result is None


class TestGetStatus:
    def test_get_status(self, attack):
        attack.iv_count = 42
        attack.unique_ivs = {b"\x01\x02\x03\x00", b"\x04\x05\x06\x00"}
        attack._start_time = time.time() - 5
        attack._running = True

        status = attack.get_status()

        assert status["iv_count"] == 42
        assert status["unique_iv_count"] == 2
        assert "elapsed_time" in status
        assert status["elapsed_time"] >= 0
        assert status["running"] is True
        assert status["target_bssid"] == "AA:BB:CC:DD:EE:FF"


class TestLaunchAircrack:
    @patch("wep_attack.subprocess.run")
    def test_launch_aircrack_not_found(self, mock_run, attack):
        mock_run.side_effect = FileNotFoundError()
        result = attack._launch_aircrack("/tmp/capture.pcap")
        assert result is None

    @patch("wep_attack.subprocess.run")
    def test_launch_aircrack_key_found(self, mock_run, attack):
        mock_result = MagicMock()
        mock_result.stdout = "KEY FOUND! [ 12:34:56:78:90 ]"
        mock_run.return_value = mock_result

        result = attack._launch_aircrack("/tmp/capture.pcap")

        assert result == "12:34:56:78:90"


class TestCLI:
    def test_cli_mode_choices(self):
        assert set(ATTACK_MODES) == {"arp-replay", "chopchop", "fragmentation", "ptw"}

        test_args = [
            "wep_attack.py", "-i", "wlan0mon", "-b", "AA:BB:CC:DD:EE:FF",
            "-m", "bogus-mode",
        ]
        with patch.object(sys, "argv", test_args):
            with pytest.raises(SystemExit):
                main()

    @patch("wep_attack.WEPAttack.start")
    @patch("wep_attack.require_root")
    def test_cli_target_ivs(self, mock_require_root, mock_start):
        test_args = [
            "wep_attack.py", "-i", "wlan0mon", "-b", "AA:BB:CC:DD:EE:FF",
            "--target-ivs", "12345",
        ]
        captured = {}

        def _fake_start(self_obj=None):
            captured["target_ivs"] = args_holder[0].target_ivs
            return {}

        import wep_attack as wep_module
        args_holder = []
        orig_init = wep_module.WEPAttack.__init__

        def spy_init(self, *a, **kw):
            orig_init(self, *a, **kw)
            args_holder.append(self)

        with patch.object(sys, "argv", test_args), \
             patch.object(wep_module.WEPAttack, "__init__", spy_init):
            main()

        assert args_holder[0].target_ivs == 12345
