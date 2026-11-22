"""Tests for handshake_capture.py -- EAPOL Handshake Verification (Feature 4)."""

import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing (module-level, as other test files do)
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.layers.eap", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.utils", MagicMock())
sys.modules.setdefault("scapy.packet", MagicMock())

from handshake_capture import HandshakeCapture, main  # noqa: E402

# Import mocked classes as production code sees them
from scapy.layers.dot11 import Dot11  # noqa: E402
from scapy.layers.eap import EAPOL  # noqa: E402


TARGET_BSSID = "AA:BB:CC:DD:EE:FF"
CLIENT_MAC = "11:22:33:44:55:66"

# Key Info bit masks (mirrors production constants)
ACK = 0x0080
MIC = 0x0100
SECURE = 0x0200
INSTALL = 0x0040
PAIRWISE = 0x0008

ANONCE = bytes(range(32))
SNONCE = bytes(range(32, 64))
NONZERO_MIC = b"\xAB" * 16
ZERO_MIC = b"\x00" * 16


def _build_eapol_body(key_info: int, replay_counter: int = 1,
                       nonce: bytes = None, mic: bytes = None) -> bytes:
    """Build a raw EAPOL-Key frame body matching the offsets in the spec."""
    if nonce is None:
        nonce = b"\x00" * 32
    if mic is None:
        mic = b"\x00" * 16

    descriptor_type = b"\x02"
    key_info_bytes = key_info.to_bytes(2, "big")
    key_length = b"\x00\x10"
    replay_counter_bytes = replay_counter.to_bytes(8, "big")
    key_iv = b"\x00" * 16
    key_rsc = b"\x00" * 8
    key_id = b"\x00" * 8
    key_data_length = b"\x00\x00"

    body = (
        descriptor_type
        + key_info_bytes
        + key_length
        + replay_counter_bytes
        + nonce
        + key_iv
        + key_rsc
        + key_id
        + mic
        + key_data_length
    )
    return body


def _make_frame(eapol_data: bytes, addr1=CLIENT_MAC, addr2=TARGET_BSSID, addr3=TARGET_BSSID):
    """Create a mock frame carrying EAPOL body bytes and Dot11 addresses."""
    frame = MagicMock()
    layers_present = {EAPOL, Dot11}
    frame.haslayer = lambda cls: cls in layers_present

    dot11 = MagicMock()
    dot11.addr1 = addr1
    dot11.addr2 = addr2
    dot11.addr3 = addr3

    eapol_layer = MagicMock()
    eapol_layer.payload = eapol_data

    def getitem(self, cls):
        if cls is Dot11:
            return dot11
        if cls is EAPOL:
            return eapol_layer
        return MagicMock()

    frame.__getitem__ = getitem
    return frame


@pytest.fixture
def capturer(mock_interface, tmp_path):
    return HandshakeCapture(
        interface=mock_interface,
        target_bssid=TARGET_BSSID,
        output_dir=str(tmp_path / "captures"),
        timeout=10,
    )


def _msg1_frame(replay_counter=1, anonce=ANONCE):
    key_info = PAIRWISE | ACK
    data = _build_eapol_body(key_info, replay_counter=replay_counter, nonce=anonce)
    return _make_frame(data, addr1=CLIENT_MAC, addr2=TARGET_BSSID)


def _msg2_frame(replay_counter=1, snonce=SNONCE, mic=NONZERO_MIC):
    key_info = PAIRWISE | MIC
    data = _build_eapol_body(key_info, replay_counter=replay_counter, nonce=snonce, mic=mic)
    return _make_frame(data, addr1=TARGET_BSSID, addr2=CLIENT_MAC)


def _msg3_frame(replay_counter=2, anonce=ANONCE, mic=NONZERO_MIC):
    key_info = PAIRWISE | ACK | MIC | INSTALL
    data = _build_eapol_body(key_info, replay_counter=replay_counter, nonce=anonce, mic=mic)
    return _make_frame(data, addr1=CLIENT_MAC, addr2=TARGET_BSSID)


def _msg4_frame(replay_counter=2, mic=NONZERO_MIC):
    key_info = PAIRWISE | MIC | SECURE
    data = _build_eapol_body(key_info, replay_counter=replay_counter, mic=mic)
    return _make_frame(data, addr1=TARGET_BSSID, addr2=CLIENT_MAC)


class TestClassifyEapolMessage:
    def test_classify_eapol_msg1(self, capturer):
        data = _build_eapol_body(PAIRWISE | ACK)
        assert capturer.classify_eapol_message(data) == 1

    def test_classify_eapol_msg2(self, capturer):
        data = _build_eapol_body(PAIRWISE | MIC, mic=NONZERO_MIC)
        assert capturer.classify_eapol_message(data) == 2

    def test_classify_eapol_msg3(self, capturer):
        data = _build_eapol_body(PAIRWISE | ACK | MIC | INSTALL, mic=NONZERO_MIC)
        assert capturer.classify_eapol_message(data) == 3

    def test_classify_eapol_msg4(self, capturer):
        data = _build_eapol_body(PAIRWISE | MIC | SECURE, mic=NONZERO_MIC)
        assert capturer.classify_eapol_message(data) == 4


class TestVerifyHandshake:
    def test_verify_complete_handshake(self, capturer):
        frames = [
            _msg1_frame(replay_counter=1),
            _msg2_frame(replay_counter=1),
            _msg3_frame(replay_counter=2),
            _msg4_frame(replay_counter=2),
        ]
        result = capturer.verify_handshake(frames)
        assert result["valid"] is True
        assert result["has_complete_handshake"] is True
        assert result["msg1_count"] == 1
        assert result["msg2_count"] == 1
        assert result["msg3_count"] == 1
        assert result["msg4_count"] == 1
        assert result["errors"] == []

    def test_verify_incomplete_handshake(self, capturer):
        frames = [
            _msg1_frame(replay_counter=1),
            _msg2_frame(replay_counter=1),
        ]
        result = capturer.verify_handshake(frames)
        assert result["valid"] is False
        assert result["has_complete_handshake"] is False
        assert len(result["errors"]) > 0

    def test_verify_nonce_mismatch(self, capturer):
        other_anonce = bytes(range(64, 96))
        frames = [
            _msg1_frame(replay_counter=1, anonce=ANONCE),
            _msg2_frame(replay_counter=1),
            _msg3_frame(replay_counter=2, anonce=other_anonce),
            _msg4_frame(replay_counter=2),
        ]
        result = capturer.verify_handshake(frames)
        assert result["nonce_consistent"] is False
        assert result["valid"] is False

    def test_verify_mic_zero_in_msg2(self, capturer):
        frames = [
            _msg1_frame(replay_counter=1),
            _msg2_frame(replay_counter=1, mic=ZERO_MIC),
            _msg3_frame(replay_counter=2),
            _msg4_frame(replay_counter=2),
        ]
        result = capturer.verify_handshake(frames)
        assert result["mic_present"] is False
        assert result["valid"] is False


class TestCheckReplayCounters:
    def test_check_replay_counter_valid(self, capturer):
        classified = capturer._classify_eapol_messages([
            _msg1_frame(replay_counter=1),
            _msg2_frame(replay_counter=1),
            _msg3_frame(replay_counter=2),
            _msg4_frame(replay_counter=2),
        ])
        assert capturer._check_replay_counters(classified) is True

    def test_check_replay_counter_invalid(self, capturer):
        classified = capturer._classify_eapol_messages([
            _msg1_frame(replay_counter=5),
            _msg2_frame(replay_counter=3),
            _msg3_frame(replay_counter=2),
            _msg4_frame(replay_counter=1),
        ])
        assert capturer._check_replay_counters(classified) is False


class TestExtractHandshakeParams:
    def test_extract_handshake_params(self, capturer):
        classified = capturer._classify_eapol_messages([
            _msg1_frame(replay_counter=1, anonce=ANONCE),
            _msg2_frame(replay_counter=1, snonce=SNONCE),
            _msg3_frame(replay_counter=2, anonce=ANONCE),
            _msg4_frame(replay_counter=2),
        ])
        params = capturer._extract_handshake_params(classified)
        assert params["anonce"] == ANONCE.hex()
        assert params["snonce"] == SNONCE.hex()
        assert params["ap_mac"] == TARGET_BSSID
        assert params["client_mac"] == CLIENT_MAC


class TestVerifyPcapFile:
    @patch("handshake_capture.rdpcap")
    def test_verify_from_pcap_file(self, mock_rdpcap, capturer):
        frames = [
            _msg1_frame(replay_counter=1),
            _msg2_frame(replay_counter=1),
            _msg3_frame(replay_counter=2),
            _msg4_frame(replay_counter=2),
        ]
        mock_rdpcap.return_value = frames
        result = capturer.verify_pcap_file("/tmp/fake.pcap")
        mock_rdpcap.assert_called_once_with("/tmp/fake.pcap")
        assert result["valid"] is True


class TestCLIVerifyFlags:
    @patch("handshake_capture.HandshakeCapture.verify_pcap_file")
    def test_cli_verify_flag(self, mock_verify, monkeypatch):
        mock_verify.return_value = {
            "valid": True, "msg1_count": 1, "msg2_count": 1,
            "msg3_count": 1, "msg4_count": 1,
            "has_complete_handshake": True, "nonce_consistent": True,
            "replay_counter_valid": True, "mic_present": True,
            "ap_mac": TARGET_BSSID, "client_mac": CLIENT_MAC,
            "anonce": "aa", "snonce": "bb", "errors": [],
        }
        monkeypatch.setattr(sys, "argv", ["handshake_capture.py", "--verify", "/tmp/fake.pcap"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        mock_verify.assert_called_once_with("/tmp/fake.pcap")

    @patch("handshake_capture.HandshakeCapture.save_capture")
    @patch("handshake_capture.HandshakeCapture.verify_handshake")
    @patch("handshake_capture.HandshakeCapture.start")
    @patch("handshake_capture.check_monitor_mode")
    @patch("handshake_capture.require_root")
    def test_cli_verify_captured_flag(self, mock_require_root, mock_check_mon,
                                       mock_start, mock_verify, mock_save,
                                       monkeypatch):
        mock_check_mon.return_value = True
        mock_start.return_value = True
        mock_save.return_value = "/tmp/captures/handshake_x.pcap"
        mock_verify.return_value = {"valid": True, "errors": []}

        monkeypatch.setattr(sys, "argv", [
            "handshake_capture.py",
            "-i", "wlan0mon", "-b", TARGET_BSSID,
            "--verify-captured",
        ])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        mock_verify.assert_called_once()
