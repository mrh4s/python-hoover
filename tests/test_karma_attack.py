"""Tests for karma_attack.py — Karma Attack."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

# Import mocked classes
from scapy.layers.dot11 import Dot11, Dot11ProbeReq  # noqa: E402

from karma_attack import DEFAULT_BLACKLIST, KarmaAttack  # noqa: E402


@pytest.fixture
def karma(mock_interface, tmp_path):
    return KarmaAttack(
        interface=mock_interface,
        log_file=str(tmp_path / "karma.log"),
        bssid="02:00:00:00:00:01",
    )


def _make_probe_packet(client_mac="11:22:33:44:55:66", ssid="TargetNet"):
    """Create a mock Dot11ProbeReq packet."""
    pkt = MagicMock()

    layers_present = {Dot11ProbeReq, Dot11}
    pkt.haslayer = lambda cls: cls in layers_present

    dot11 = MagicMock()
    dot11.addr2 = client_mac
    pkt.__getitem__ = lambda self, cls: dot11

    # SSID element chain
    ssid_elt = MagicMock()
    ssid_elt.ID = 0
    ssid_elt.info = ssid.encode() if ssid else b""

    end_elt = MagicMock()
    end_elt.ID = 255
    end_elt.payload = MagicMock()
    end_elt.payload.getlayer = MagicMock(return_value=None)
    ssid_elt.payload = MagicMock()
    ssid_elt.payload.getlayer = MagicMock(return_value=end_elt)

    pkt.getlayer = MagicMock(return_value=ssid_elt)

    return pkt


class TestKarmaAttackInit:
    def test_defaults(self, mock_interface):
        k = KarmaAttack(interface=mock_interface)
        assert k.interface == mock_interface
        assert k.channel == 6
        assert k.whitelist is None
        assert k.blacklist == DEFAULT_BLACKLIST
        assert k.responded_count == 0
        assert k.seen_probes == {}

    def test_custom_bssid(self, mock_interface):
        k = KarmaAttack(interface=mock_interface, bssid="02:aa:bb:cc:dd:ee")
        assert k.bssid == "02:aa:bb:cc:dd:ee"


class TestGenerateBSSID:
    def test_format(self):
        bssid = KarmaAttack._generate_bssid()
        parts = bssid.split(":")
        assert len(parts) == 6
        assert parts[0] == "02"
        for part in parts:
            assert len(part) == 2
            int(part, 16)


class TestPacketHandler:
    @patch("karma_attack.sendp")
    def test_responds_to_probe(self, mock_sendp, karma):
        pkt = _make_probe_packet()
        karma.packet_handler(pkt)
        assert mock_sendp.call_count == 2
        assert karma.responded_count == 1
        assert "11:22:33:44:55:66" in karma.seen_probes
        assert "TargetNet" in karma.seen_probes["11:22:33:44:55:66"]

    @patch("karma_attack.sendp")
    def test_respects_blacklist(self, mock_sendp, mock_interface, tmp_path):
        k = KarmaAttack(
            interface=mock_interface,
            blacklist=["BlockedNet"],
            log_file=str(tmp_path / "karma.log"),
        )
        pkt = _make_probe_packet(ssid="BlockedNet")
        k.packet_handler(pkt)
        mock_sendp.assert_not_called()
        assert k.responded_count == 0

    @patch("karma_attack.sendp")
    def test_respects_whitelist(self, mock_sendp, mock_interface, tmp_path):
        k = KarmaAttack(
            interface=mock_interface,
            whitelist=["AllowedNet"],
            log_file=str(tmp_path / "karma.log"),
            bssid="02:00:00:00:00:01",
        )
        pkt = _make_probe_packet(ssid="AllowedNet")
        k.packet_handler(pkt)
        assert mock_sendp.call_count == 2

        mock_sendp.reset_mock()
        pkt2 = _make_probe_packet(ssid="OtherNet")
        k.packet_handler(pkt2)
        mock_sendp.assert_not_called()

    @patch("karma_attack.sendp")
    def test_empty_ssid_ignored(self, mock_sendp, karma):
        pkt = _make_probe_packet(ssid="")
        karma.packet_handler(pkt)
        mock_sendp.assert_not_called()

    @patch("karma_attack.sendp")
    def test_non_probe_ignored(self, mock_sendp, karma):
        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=False)
        karma.packet_handler(pkt)
        mock_sendp.assert_not_called()

    @patch("karma_attack.sendp")
    def test_tracks_multiple_ssids(self, mock_sendp, karma):
        karma.packet_handler(_make_probe_packet(ssid="Net1"))
        karma.packet_handler(_make_probe_packet(ssid="Net2"))
        client_probes = karma.seen_probes["11:22:33:44:55:66"]
        assert "Net1" in client_probes
        assert "Net2" in client_probes


class TestCreateFrames:
    def test_create_probe_response(self, karma):
        resp = karma._create_probe_response("TestSSID", "11:22:33:44:55:66")
        assert resp is not None

    def test_create_beacon(self, karma):
        beacon = karma._create_beacon("TestSSID")
        assert beacon is not None


class TestPrintSummary:
    @patch("karma_attack.lookup_vendor", return_value="TestVendor")
    def test_print(self, mock_vendor, karma, capsys):
        karma.seen_probes = {"AA:BB:CC:DD:EE:FF": {"Net1", "Net2"}}
        karma.responded_count = 5
        karma.print_summary()
        captured = capsys.readouterr()
        assert "Unique clients" in captured.out
        assert "5" in captured.out


class TestSaveLog:
    @patch("karma_attack.lookup_vendor", return_value="TestVendor")
    def test_save(self, mock_vendor, karma):
        karma.seen_probes = {"AA:BB:CC:DD:EE:FF": {"Net1"}}
        karma.responded_count = 1
        karma.save_log()
        assert os.path.exists(karma.log_file)
        with open(karma.log_file) as f:
            content = f.read()
        assert "AA:BB:CC:DD:EE:FF" in content

    def test_save_empty(self, karma):
        karma.save_log()
