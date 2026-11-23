"""Tests for krack.py — KRACK (Key Reinstallation Attack) Detection module."""

import json
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
sys.modules.setdefault("scapy.packet", MagicMock())

# Import mocked classes as production code sees them
from scapy.layers.dot11 import Dot11  # noqa: E402
from scapy.layers.eap import EAPOL  # noqa: E402

from krack import (  # noqa: E402
    KEY_INFO_ACK,
    KEY_INFO_INSTALL,
    KEY_INFO_MIC,
    KEY_INFO_SECURE,
    KRACKDetector,
    main,
)

BSSID = "AA:BB:CC:DD:EE:FF"
CLIENT = "11:22:33:44:55:66"


def _eapol_body(
    key_info: int, replay_counter: int = 1, nonce: bytes = b"\x00" * 32, mic: bytes = b"\x00" * 16
) -> bytes:
    """Build a realistic EAPOL Key frame body for the given key_info bits."""
    body = bytearray(95)
    body[0] = 0x02  # descriptor type (RSN)
    body[1:3] = key_info.to_bytes(2, "big")
    body[5:13] = replay_counter.to_bytes(8, "big")
    body[13:45] = nonce.ljust(32, b"\x00")[:32]
    body[77:93] = mic.ljust(16, b"\x00")[:16]
    return bytes(body)


class _FakeEAPOLLayer:
    """A minimal stand-in for scapy's EAPOL layer that supports bytes().

    MagicMock does not support assigning ``__bytes__`` on an instance
    (dunder lookups go through the type), so a tiny real class is used
    instead wherever the module under test needs real byte content.
    """

    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def __bytes__(self) -> bytes:
        return self._raw


def _make_eapol_packet(
    key_info: int,
    replay_counter: int = 1,
    nonce: bytes = b"\x00" * 32,
    bssid: str = BSSID,
    client: str = CLIENT,
    has_eapol: bool = True,
    has_dot11: bool = True,
):
    """Create a mock packet carrying an EAPOL Key frame between bssid/client."""
    pkt = MagicMock()

    eapol_body = _eapol_body(key_info, replay_counter, nonce)
    eapol_raw = b"\x01\x03" + len(eapol_body).to_bytes(2, "big") + eapol_body

    eapol_layer = _FakeEAPOLLayer(eapol_raw)

    dot11_layer = MagicMock()
    dot11_layer.addr1 = client
    dot11_layer.addr2 = bssid
    dot11_layer.addr3 = bssid

    layers_present = set()
    if has_eapol:
        layers_present.add(EAPOL)
    if has_dot11:
        layers_present.add(Dot11)

    pkt.haslayer = lambda cls: cls in layers_present

    def getitem(self, cls):
        if cls is EAPOL:
            return eapol_layer
        if cls is Dot11:
            return dot11_layer
        return MagicMock()

    pkt.__getitem__ = getitem

    return pkt


def _msg1_packet(**kwargs):
    return _make_eapol_packet(key_info=KEY_INFO_ACK, **kwargs)


def _msg2_packet(**kwargs):
    return _make_eapol_packet(key_info=KEY_INFO_MIC, **kwargs)


def _msg3_packet(nonce=b"\xaa" * 32, **kwargs):
    return _make_eapol_packet(
        key_info=(KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_INSTALL), nonce=nonce, **kwargs
    )


def _msg4_packet(**kwargs):
    return _make_eapol_packet(key_info=(KEY_INFO_MIC | KEY_INFO_SECURE), **kwargs)


def _make_non_eapol_packet():
    pkt = MagicMock()
    pkt.haslayer = lambda cls: False
    return pkt


@pytest.fixture
def detector(mock_interface, tmp_path):
    return KRACKDetector(
        interface=mock_interface,
        target_bssid=BSSID,
        target_client=CLIENT,
        channel=6,
        timeout=180,
        output_dir=str(tmp_path / "captures"),
        test_mode="4way",
    )


# ---------------------------------------------------------------------------
# 1. Init defaults
# ---------------------------------------------------------------------------
class TestInit:
    def test_init_defaults(self, mock_interface):
        d = KRACKDetector(interface=mock_interface, target_bssid=BSSID)
        assert d.interface == mock_interface
        assert d.target_bssid == BSSID
        assert d.target_client is None
        assert d.channel is None
        assert d.timeout == 180
        assert d.output_dir == "captures"
        assert d.test_mode == "4way"
        assert d.detect_only is False
        assert d.vulnerable is False
        assert d.findings == []
        assert d.eapol_frames == []


# ---------------------------------------------------------------------------
# 2-3. EAPOL key info parsing
# ---------------------------------------------------------------------------
class TestParseEapolKeyInfo:
    def test_parse_eapol_key_info_msg1(self, detector):
        body = _eapol_body(KEY_INFO_ACK)
        parsed = detector._parse_eapol_key_info(body)
        assert parsed["key_info"] & KEY_INFO_ACK
        assert not (parsed["key_info"] & KEY_INFO_MIC)

    def test_parse_eapol_key_info_msg3(self, detector):
        body = _eapol_body(KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_INSTALL)
        parsed = detector._parse_eapol_key_info(body)
        assert parsed["key_info"] & KEY_INFO_INSTALL
        assert parsed["key_info"] & KEY_INFO_ACK
        assert parsed["key_info"] & KEY_INFO_MIC


# ---------------------------------------------------------------------------
# 4. Track sequence msg1-4
# ---------------------------------------------------------------------------
class TestTrackEapolSequence:
    def test_track_eapol_sequence_msg1_through_4(self, detector):
        for pkt in (_msg1_packet(), _msg2_packet(), _msg3_packet(), _msg4_packet()):
            detector._track_eapol_sequence(pkt)

        key = (BSSID, CLIENT)
        assert detector._eapol_sequences[key] == [1, 2, 3, 4]


# ---------------------------------------------------------------------------
# 5-6. Key reinstallation detection
# ---------------------------------------------------------------------------
class TestDetectKeyReinstallation:
    def test_detect_key_reinstallation_with_replayed_msg3(self, detector):
        nonce = b"\xaa" * 32
        for pkt in (
            _msg1_packet(),
            _msg2_packet(),
            _msg3_packet(nonce=nonce),
            _msg4_packet(),
            _msg3_packet(nonce=nonce),  # replayed msg3 with same ANonce
        ):
            detector._track_eapol_sequence(pkt)

        assert detector._detect_key_reinstallation() is True
        assert detector.vulnerable is True
        assert len(detector.findings) >= 1

    def test_no_false_positive_on_normal_handshake(self, detector):
        for pkt in (_msg1_packet(), _msg2_packet(), _msg3_packet(), _msg4_packet()):
            detector._track_eapol_sequence(pkt)

        assert detector._detect_key_reinstallation() is False
        assert detector.vulnerable is False
        assert detector.findings == []


# ---------------------------------------------------------------------------
# 7. Nonce reuse monitoring
# ---------------------------------------------------------------------------
class TestMonitorNonceReuse:
    def test_monitor_nonce_reuse_flags_duplicate(self, detector):
        nonce = b"\xbb" * 32
        for pkt in (
            _msg1_packet(),
            _msg2_packet(),
            _msg3_packet(nonce=nonce),
            _msg4_packet(),
            _msg3_packet(nonce=nonce),
        ):
            detector._track_eapol_sequence(pkt)

        report = detector._monitor_nonce_reuse()
        key = str((BSSID, CLIENT))
        assert key in report
        assert report[key]["duplicate_found"] is True
        assert report[key]["total_nonces"] == 2


# ---------------------------------------------------------------------------
# 8-9. packet_handler filtering
# ---------------------------------------------------------------------------
class TestPacketHandler:
    def test_packet_handler_ignores_non_eapol(self, detector):
        pkt = _make_non_eapol_packet()
        detector.packet_handler(pkt)
        assert detector.eapol_frames == []

    def test_packet_handler_filters_by_bssid(self, detector):
        pkt = _msg1_packet(bssid="99:99:99:99:99:99")
        detector.packet_handler(pkt)
        assert detector.eapol_frames == []

    def test_packet_handler_captures_matching_traffic(self, detector):
        pkt = _msg1_packet()
        detector.packet_handler(pkt)
        assert len(detector.eapol_frames) == 1


# ---------------------------------------------------------------------------
# 10. save_results
# ---------------------------------------------------------------------------
class TestSaveResults:
    def test_save_results_writes_json(self, detector, tmp_path):
        pkt = _msg1_packet()
        detector.packet_handler(pkt)
        detector.findings.append({"type": "test_finding"})

        with patch("krack.wrpcap"):
            filepath = detector.save_results()

        assert filepath is not None
        assert os.path.exists(filepath)
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        assert data["target_bssid"] == BSSID
        assert data["findings"] == [{"type": "test_finding"}]

    def test_save_results_returns_none_when_empty(self, detector):
        assert detector.save_results() is None


# ---------------------------------------------------------------------------
# 11. get_status
# ---------------------------------------------------------------------------
class TestGetStatus:
    def test_get_status_during_detection(self, detector):
        status = detector.get_status()
        assert status["running"] is False
        assert status["interface"] == detector.interface
        assert status["target_bssid"] == BSSID
        assert status["target_client"] == CLIENT
        assert status["mode"] == "4way"
        assert status["detect_only"] is False
        assert status["frames_captured"] == 0
        assert status["vulnerable"] is False
        assert "elapsed_seconds" in status
        assert status["timeout"] == 180


# ---------------------------------------------------------------------------
# 12-13. CLI behavior
# ---------------------------------------------------------------------------
class TestCLI:
    def test_cli_detect_only_flag(self, tmp_path):
        test_args = [
            "krack.py",
            "-i",
            "wlan0mon",
            "-b",
            BSSID,
            "--detect-only",
            "-t",
            "1",
        ]
        fake_results = {
            "vulnerable": False,
            "findings": [],
            "nonce_report": {},
            "frames_captured": 0,
            "mode": "4way",
        }
        with (
            patch.object(sys, "argv", test_args),
            patch("krack.require_root"),
            patch("krack.KRACKDetector.start", return_value=fake_results) as mock_start,
            patch("krack.KRACKDetector.save_results", return_value=None),
            patch("krack.sys.exit"),
        ):
            main()

        mock_start.assert_called_once()

    def test_cli_mode_choices(self):
        test_args = [
            "krack.py",
            "-i",
            "wlan0mon",
            "-b",
            BSSID,
            "-m",
            "invalid_mode",
        ]
        with patch.object(sys, "argv", test_args):
            with pytest.raises(SystemExit):
                main()

    def test_cli_required_args_missing(self):
        test_args = ["krack.py"]
        with patch.object(sys, "argv", test_args):
            with pytest.raises(SystemExit):
                main()
