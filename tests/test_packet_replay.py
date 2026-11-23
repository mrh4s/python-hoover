"""Tests for packet_replay.py — WiFi Packet Capture and Replay."""

import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.layers.eap", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.utils", MagicMock())


from packet_replay import FILTER_TYPES, PacketReplay  # noqa: E402


@pytest.fixture
def mock_interface():
    return "wlan0mon"


@pytest.fixture
def replayer(mock_interface):
    return PacketReplay(interface=mock_interface)


@pytest.fixture
def replayer_with_pcap(mock_interface):
    return PacketReplay(interface=mock_interface, pcap_file="test.pcap")


class TestPacketReplayInit:
    def test_default_init(self, mock_interface):
        r = PacketReplay(interface=mock_interface)
        assert r.interface == mock_interface
        assert r.pcap_file is None
        assert r.capture_timeout == 30
        assert r.replay_count == 1
        assert r.replay_delay == 0.1
        assert r.filter_type is None
        assert r.filter_mac is None
        assert r.captured_packets == []
        assert r.packets_sent == 0

    def test_custom_init(self, mock_interface):
        r = PacketReplay(
            interface=mock_interface,
            pcap_file="capture.pcap",
            capture_timeout=60,
            replay_count=5,
            replay_delay=0.5,
            filter_type="beacon",
            filter_mac="AA:BB:CC:DD:EE:FF",
        )
        assert r.pcap_file == "capture.pcap"
        assert r.capture_timeout == 60
        assert r.replay_count == 5
        assert r.replay_delay == 0.5
        assert r.filter_type == "beacon"
        assert r.filter_mac == "AA:BB:CC:DD:EE:FF"


class TestCapture:
    @patch("packet_replay.sniff")
    def test_capture_returns_packets(self, mock_sniff, replayer):
        mock_pkt1 = MagicMock()
        mock_pkt2 = MagicMock()
        mock_sniff.return_value = [mock_pkt1, mock_pkt2]

        result = replayer.capture()
        assert len(result) == 2
        assert replayer._stats["packets_captured"] == 2
        mock_sniff.assert_called_once()

    @patch("packet_replay.sniff")
    def test_capture_empty(self, mock_sniff, replayer):
        mock_sniff.return_value = []
        result = replayer.capture()
        assert result == []
        assert replayer._stats["packets_captured"] == 0

    @patch("packet_replay.sniff")
    def test_capture_uses_timeout(self, mock_sniff, mock_interface):
        r = PacketReplay(interface=mock_interface, capture_timeout=60)
        mock_sniff.return_value = []
        r.capture()
        args, kwargs = mock_sniff.call_args
        assert kwargs["timeout"] == 60


class TestLoadSavePcap:
    @patch("packet_replay.rdpcap")
    @patch("os.path.isfile", return_value=True)
    def test_load_pcap(self, mock_isfile, mock_rdpcap, replayer):
        mock_pkt = MagicMock()
        mock_rdpcap.return_value = [mock_pkt]
        result = replayer.load_pcap("test.pcap")
        assert len(result) == 1
        mock_rdpcap.assert_called_once_with("test.pcap")

    @patch("os.path.isfile", return_value=False)
    def test_load_pcap_file_not_found(self, mock_isfile, replayer):
        result = replayer.load_pcap("nonexistent.pcap")
        assert result == []

    @patch("packet_replay.wrpcap")
    def test_save_pcap(self, mock_wrpcap, replayer):
        packets = [MagicMock(), MagicMock()]
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "out.pcap")
            replayer.save_pcap(packets, filepath)
            mock_wrpcap.assert_called_once_with(filepath, packets)

    @patch("packet_replay.wrpcap")
    def test_save_pcap_empty(self, mock_wrpcap, replayer):
        replayer.save_pcap([], "out.pcap")
        mock_wrpcap.assert_not_called()


class TestFilterPackets:
    def test_filter_all_type(self, replayer):
        replayer.filter_type = "all"
        packets = [MagicMock(), MagicMock()]
        result = replayer.filter_packets(packets)
        assert len(result) == 2

    def test_filter_by_mac(self, mock_interface):
        r = PacketReplay(interface=mock_interface, filter_mac="AA:BB:CC:DD:EE:FF")
        pkt1 = MagicMock()
        pkt1.haslayer.return_value = True
        dot11_1 = MagicMock()
        dot11_1.addr1 = "AA:BB:CC:DD:EE:FF"
        dot11_1.addr2 = "11:22:33:44:55:66"
        dot11_1.addr3 = "11:22:33:44:55:66"
        pkt1.__getitem__ = lambda self, key: dot11_1

        pkt2 = MagicMock()
        pkt2.haslayer.return_value = True
        dot11_2 = MagicMock()
        dot11_2.addr1 = "11:22:33:44:55:66"
        dot11_2.addr2 = "11:22:33:44:55:66"
        dot11_2.addr3 = "11:22:33:44:55:66"
        pkt2.__getitem__ = lambda self, key: dot11_2

        result = r.filter_packets([pkt1, pkt2])
        assert len(result) == 1

    def test_filter_no_filter(self, replayer):
        packets = [MagicMock(), MagicMock(), MagicMock()]
        result = replayer.filter_packets(packets)
        assert len(result) == 3


class TestReplay:
    @patch("packet_replay.sendp")
    @patch("packet_replay.time.sleep")
    def test_replay_sends_packets(self, mock_sleep, mock_sendp, replayer):
        packets = [MagicMock(), MagicMock()]
        count = replayer.replay(packets)
        assert count == 2
        assert mock_sendp.call_count == 2

    @patch("packet_replay.sendp")
    @patch("packet_replay.time.sleep")
    def test_replay_multiple_iterations(self, mock_sleep, mock_sendp, mock_interface):
        r = PacketReplay(interface=mock_interface, replay_count=3)
        packets = [MagicMock()]
        count = r.replay(packets)
        assert count == 3
        assert mock_sendp.call_count == 3

    @patch("packet_replay.sendp")
    @patch("packet_replay.time.sleep")
    def test_replay_empty(self, mock_sleep, mock_sendp, replayer):
        count = replayer.replay([])
        assert count == 0
        mock_sendp.assert_not_called()

    @patch("packet_replay.sendp")
    @patch("packet_replay.time.sleep")
    def test_replay_stops_on_event(self, mock_sleep, mock_sendp, replayer):
        replayer._stop_event.set()
        count = replayer.replay([MagicMock()])
        assert count == 0


class TestStats:
    def test_initial_stats(self, replayer):
        stats = replayer.get_stats()
        assert stats["packets_captured"] == 0
        assert stats["packets_filtered"] == 0
        assert stats["packets_replayed"] == 0

    @patch("packet_replay.sniff")
    def test_stats_after_capture(self, mock_sniff, replayer):
        mock_sniff.return_value = [MagicMock(), MagicMock(), MagicMock()]
        replayer.capture()
        assert replayer.get_stats()["packets_captured"] == 3


class TestStop:
    def test_stop_sets_event(self, replayer):
        assert not replayer._stop_event.is_set()
        replayer.stop()
        assert replayer._stop_event.is_set()


class TestFilterTypes:
    def test_all_filter_types_exist(self):
        assert "beacon" in FILTER_TYPES
        assert "probe" in FILTER_TYPES
        assert "deauth" in FILTER_TYPES
        assert "eapol" in FILTER_TYPES
        assert "all" in FILTER_TYPES

    def test_all_filter_accepts_everything(self):
        pkt = MagicMock()
        assert FILTER_TYPES["all"](pkt) is True


class TestPrintSummary:
    def test_print_summary_no_error(self, replayer, capsys):
        replayer.print_summary()
        output = capsys.readouterr().out
        assert "Packet Replay Summary" in output
