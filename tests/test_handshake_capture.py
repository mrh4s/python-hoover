"""Tests for handshake_capture.py — WPA Handshake Capture."""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.layers.eap", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.utils", MagicMock())

from handshake_capture import HandshakeCapture  # noqa: E402

# Import mocked classes as production code sees them
from scapy.layers.dot11 import Dot11  # noqa: E402
from scapy.layers.eap import EAPOL  # noqa: E402


TARGET_BSSID = "AA:BB:CC:DD:EE:FF"
CLIENT_MAC = "11:22:33:44:55:66"


@pytest.fixture
def capturer(mock_interface, tmp_path):
    return HandshakeCapture(
        interface=mock_interface,
        target_bssid=TARGET_BSSID,
        output_dir=str(tmp_path / "captures"),
        timeout=10,
    )


@pytest.fixture
def capturer_with_client(mock_interface, tmp_path):
    return HandshakeCapture(
        interface=mock_interface,
        target_bssid=TARGET_BSSID,
        target_client=CLIENT_MAC,
        output_dir=str(tmp_path / "captures"),
        timeout=10,
    )


def _make_eapol_packet(addr1="11:22:33:44:55:66",
                        addr2="AA:BB:CC:DD:EE:FF",
                        addr3="AA:BB:CC:DD:EE:FF"):
    """Create a mock EAPOL packet."""
    pkt = MagicMock()

    layers_present = {EAPOL, Dot11}
    pkt.haslayer = lambda cls: cls in layers_present

    dot11 = MagicMock()
    dot11.addr1 = addr1
    dot11.addr2 = addr2
    dot11.addr3 = addr3

    def getitem(self, cls):
        if cls is Dot11:
            return dot11
        return MagicMock()
    pkt.__getitem__ = getitem

    return pkt


class TestHandshakeCaptureInit:
    def test_defaults(self, mock_interface):
        c = HandshakeCapture(interface=mock_interface, target_bssid=TARGET_BSSID)
        assert c.interface == mock_interface
        assert c.target_bssid == TARGET_BSSID
        assert c.target_client is None
        assert c.timeout == 120
        assert c.deauth_count == 5
        assert c.handshake_complete is False
        assert c.eapol_frames == []

    def test_bssid_uppercased(self, mock_interface):
        c = HandshakeCapture(interface=mock_interface, target_bssid="aa:bb:cc:dd:ee:ff")
        assert c.target_bssid == "AA:BB:CC:DD:EE:FF"

    def test_client_uppercased(self, mock_interface):
        c = HandshakeCapture(
            interface=mock_interface, target_bssid=TARGET_BSSID,
            target_client="aa:bb:cc:dd:ee:ff",
        )
        assert c.target_client == "AA:BB:CC:DD:EE:FF"


class TestPacketHandler:
    def test_eapol_frame_added(self, capturer):
        pkt = _make_eapol_packet()
        capturer.packet_handler(pkt)
        assert len(capturer.eapol_frames) == 1

    def test_wrong_bssid_ignored(self, capturer):
        pkt = _make_eapol_packet(addr1="99:99:99:99:99:99",
                                  addr2="99:99:99:99:99:99",
                                  addr3="99:99:99:99:99:99")
        capturer.packet_handler(pkt)
        assert len(capturer.eapol_frames) == 0

    def test_four_frames_complete_handshake(self, capturer):
        for _ in range(4):
            pkt = _make_eapol_packet()
            capturer.packet_handler(pkt)
        assert capturer.handshake_complete is True
        assert capturer._stop_event.is_set()

    def test_target_client_filter(self, capturer_with_client):
        pkt = _make_eapol_packet(addr1=CLIENT_MAC)
        capturer_with_client.packet_handler(pkt)
        assert len(capturer_with_client.eapol_frames) == 1

    def test_wrong_client_ignored(self, capturer_with_client):
        pkt = _make_eapol_packet(addr1="99:99:99:99:99:99",
                                  addr2="AA:BB:CC:DD:EE:FF",
                                  addr3="AA:BB:CC:DD:EE:FF")
        capturer_with_client.packet_handler(pkt)
        assert len(capturer_with_client.eapol_frames) == 0

    def test_non_eapol_ignored(self, capturer):
        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=False)
        capturer.packet_handler(pkt)
        assert len(capturer.eapol_frames) == 0


class TestSaveCapture:
    @patch("handshake_capture.wrpcap")
    def test_save_with_frames(self, mock_wrpcap, capturer):
        capturer.eapol_frames = [MagicMock(), MagicMock()]
        filepath = capturer.save_capture()
        assert filepath is not None
        assert "handshake_" in filepath
        mock_wrpcap.assert_called_once()

    def test_save_no_frames(self, capturer):
        result = capturer.save_capture()
        assert result is None


class TestGetStatus:
    def test_status_dict(self, capturer):
        import time
        capturer._start_time = time.time()
        status = capturer.get_status()
        assert status["target_bssid"] == TARGET_BSSID
        assert status["frames_captured"] == 0
        assert status["handshake_complete"] is False
        assert "elapsed_time" in status


class TestSendDeauth:
    @patch("handshake_capture.sendp")
    def test_deauth_sends_frames(self, mock_sendp, capturer):
        def stop_after_first_call(*args, **kwargs):
            capturer._stop_event.set()
        mock_sendp.side_effect = stop_after_first_call
        capturer._send_deauth()
        assert mock_sendp.call_count >= 1


class TestStart:
    @patch("handshake_capture.sniff")
    def test_start_returns_bool(self, mock_sniff, capturer):
        mock_sniff.return_value = None
        result = capturer.start()
        assert isinstance(result, bool)

    @patch("handshake_capture.sniff")
    def test_start_no_deauth(self, mock_sniff, mock_interface, tmp_path):
        c = HandshakeCapture(
            interface=mock_interface, target_bssid=TARGET_BSSID,
            output_dir=str(tmp_path), no_deauth=True,
        )
        c.start()
        mock_sniff.assert_called_once()

    @patch("handshake_capture.sniff")
    @patch("handshake_capture.subprocess.run")
    def test_start_sets_channel(self, mock_run, mock_sniff, mock_interface, tmp_path):
        c = HandshakeCapture(
            interface=mock_interface, target_bssid=TARGET_BSSID,
            channel=11, output_dir=str(tmp_path),
        )
        c.start()
        mock_run.assert_called()
