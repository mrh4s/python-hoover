"""Tests for pmkid_capture.py — PMKID Capture module."""

import os
import sys
import time
from unittest.mock import MagicMock, patch, mock_open

import pytest

# Mock scapy before importing
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.layers.eap", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.utils", MagicMock())

from pmkid_capture import PMKIDCapture  # noqa: E402

# Import mocked classes as production code sees them
from scapy.layers.dot11 import Dot11, Dot11Elt  # noqa: E402
from scapy.layers.eap import EAPOL  # noqa: E402


TARGET_BSSID = "AA:BB:CC:DD:EE:FF"
CLIENT_MAC = "11:22:33:44:55:66"


@pytest.fixture
def capturer(mock_interface, tmp_path):
    return PMKIDCapture(
        interface=mock_interface,
        target_bssid=TARGET_BSSID,
        output_dir=str(tmp_path / "captures"),
        timeout=10,
    )


@pytest.fixture
def capturer_with_client(mock_interface, tmp_path):
    return PMKIDCapture(
        interface=mock_interface,
        target_bssid=TARGET_BSSID,
        output_dir=str(tmp_path / "captures"),
        timeout=10,
        client_mac=CLIENT_MAC,
    )


def _build_pmkid_kde(pmkid_hex: str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") -> bytes:
    """Build a PMKID KDE (Key Data Encapsulation) blob.

    Format: type(0xDD) + length(20) + OUI(00:0F:AC) + data_type(04) + 16-byte PMKID
    """
    pmkid_bytes = bytes.fromhex(pmkid_hex)
    kde = (
        b"\xdd"              # Tag type: 0xDD
        b"\x14"              # Length: 20 (3 OUI + 1 type + 16 PMKID)
        b"\x00\x0f\xac"     # OUI: 00:0F:AC
        b"\x04"              # Data type: 04 (PMKID)
    ) + pmkid_bytes
    return kde


def _build_eapol_key_data(key_data: bytes) -> bytes:
    """Build a minimal EAPOL Key frame with the given Key Data.

    Layout (99-byte header):
      version(1) + type(1) + length(2) + descriptor_type(1)
      + key_info(2) + key_length(2) + replay_counter(8)
      + nonce(32) + key_iv(16) + key_rsc(8) + key_id(8)
      + key_mic(16) + key_data_length(2) + key_data(variable)
    """
    key_data_len = len(key_data).to_bytes(2, "big")
    # 1 (version) + 1 (type=3 key) + 2 (body len) + 1 (descriptor) = 5
    # + 2 (key_info) + 2 (key_length) + 8 (replay) + 32 (nonce)
    # + 16 (iv) + 8 (rsc) + 8 (id) + 16 (mic) + 2 (key_data_len) = 94
    # Total header = 5 + 94 = 99
    header = (
        b"\x02"          # Version
        b"\x03"          # Type: EAPOL-Key
        b"\x00\x5f"     # Body length (placeholder)
        b"\x02"          # Descriptor type: RSN
        b"\x00\x8a"     # Key info (pairwise, msg1 flags)
        b"\x00\x10"     # Key length: 16
        + b"\x00" * 8   # Replay counter
        + b"\x00" * 32  # Nonce
        + b"\x00" * 16  # Key IV
        + b"\x00" * 8   # Key RSC
        + b"\x00" * 8   # Key ID
        + b"\x00" * 16  # Key MIC
        + key_data_len   # Key data length
    )
    return header + key_data


def _make_eapol_packet(addr1="11:22:33:44:55:66",
                       addr2="AA:BB:CC:DD:EE:FF",
                       addr3="AA:BB:CC:DD:EE:FF",
                       eapol_raw=None,
                       has_dot11_elt=False,
                       essid=None):
    """Create a mock EAPOL packet with optional raw EAPOL data."""
    pkt = MagicMock()

    layers_present = {EAPOL, Dot11}
    if has_dot11_elt:
        layers_present.add(Dot11Elt)

    pkt.haslayer = lambda cls: cls in layers_present

    dot11 = MagicMock()
    dot11.addr1 = addr1
    dot11.addr2 = addr2
    dot11.addr3 = addr3

    class _EAPOLBytes:
        """Lightweight stand-in whose bytes() returns the raw EAPOL data."""
        def __init__(self, raw):
            self._raw = raw
        def __bytes__(self):
            return self._raw

    if eapol_raw is not None:
        eapol_layer = _EAPOLBytes(eapol_raw)
    else:
        eapol_layer = _EAPOLBytes(b"\x00" * 50)

    dot11_elt = MagicMock()
    if essid:
        dot11_elt.ID = 0
        dot11_elt.info = essid.encode("utf-8")
    else:
        dot11_elt.ID = 0
        dot11_elt.info = b""

    def getitem(self, cls):
        if cls is Dot11:
            return dot11
        if cls is EAPOL:
            return eapol_layer
        if cls is Dot11Elt:
            return dot11_elt
        return MagicMock()

    pkt.__getitem__ = getitem

    return pkt


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPMKIDCaptureInit:
    def test_defaults(self, mock_interface):
        c = PMKIDCapture(interface=mock_interface, target_bssid=TARGET_BSSID)
        assert c.interface == mock_interface
        assert c.target_bssid == TARGET_BSSID
        assert c.channel is None
        assert c.output_dir == "captures"
        assert c.timeout == 60
        assert c.client_mac is None
        assert c.pmkid is None
        assert c.capture_complete is False
        assert c.eapol_frames == []

    def test_custom_params(self, mock_interface, tmp_path):
        c = PMKIDCapture(
            interface=mock_interface,
            target_bssid=TARGET_BSSID,
            channel=6,
            output_dir=str(tmp_path),
            timeout=120,
            client_mac=CLIENT_MAC,
        )
        assert c.channel == 6
        assert c.output_dir == str(tmp_path)
        assert c.timeout == 120
        assert c.client_mac == CLIENT_MAC.upper()

    def test_bssid_uppercased(self, mock_interface):
        c = PMKIDCapture(interface=mock_interface, target_bssid="aa:bb:cc:dd:ee:ff")
        assert c.target_bssid == "AA:BB:CC:DD:EE:FF"

    def test_client_mac_uppercased(self, mock_interface):
        c = PMKIDCapture(
            interface=mock_interface,
            target_bssid=TARGET_BSSID,
            client_mac="aa:bb:cc:dd:ee:ff",
        )
        assert c.client_mac == "AA:BB:CC:DD:EE:FF"

    def test_client_mac_none(self, mock_interface):
        c = PMKIDCapture(interface=mock_interface, target_bssid=TARGET_BSSID)
        assert c.client_mac is None


class TestExtractPMKID:
    def test_valid_pmkid_extraction(self, capturer):
        """PMKID should be extracted from a correctly formed KDE."""
        pmkid_hex = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        kde = _build_pmkid_kde(pmkid_hex)
        result = capturer._extract_pmkid(kde)
        assert result == pmkid_hex

    def test_no_pmkid_in_data(self, capturer):
        """Should return None when data contains no PMKID KDE."""
        result = capturer._extract_pmkid(b"\x00" * 50)
        assert result is None

    def test_empty_data(self, capturer):
        """Should return None for empty data."""
        result = capturer._extract_pmkid(b"")
        assert result is None

    def test_truncated_data(self, capturer):
        """Should return None for truncated KDE."""
        # Just the tag type and partial length
        result = capturer._extract_pmkid(b"\xdd\x14\x00\x0f")
        assert result is None

    def test_wrong_oui(self, capturer):
        """Should return None when OUI does not match 00:0F:AC."""
        bad_kde = (
            b"\xdd"
            b"\x14"
            b"\x00\x0f\xab"  # Wrong OUI (last byte)
            b"\x04"
            + b"\xaa" * 16
        )
        result = capturer._extract_pmkid(bad_kde)
        assert result is None

    def test_wrong_data_type(self, capturer):
        """Should return None when data type is not 04."""
        bad_kde = (
            b"\xdd"
            b"\x14"
            b"\x00\x0f\xac"
            b"\x03"           # Wrong data type
            + b"\xaa" * 16
        )
        result = capturer._extract_pmkid(bad_kde)
        assert result is None

    def test_all_zero_pmkid_rejected(self, capturer):
        """An all-zero PMKID means the AP does not support it; reject."""
        kde = _build_pmkid_kde("00000000000000000000000000000000")
        result = capturer._extract_pmkid(kde)
        assert result is None

    def test_pmkid_after_other_kde(self, capturer):
        """PMKID KDE preceded by another KDE should still be found."""
        pmkid_hex = "deadbeefcafebabe1234567890abcdef"
        # Arbitrary non-PMKID KDE first
        other_kde = b"\xdd\x06\x00\x50\xf2\x01\x01\x00"
        pmkid_kde = _build_pmkid_kde(pmkid_hex)
        result = capturer._extract_pmkid(other_kde + pmkid_kde)
        assert result == pmkid_hex

    def test_short_tag_length(self, capturer):
        """KDE with tag type 0xDD but length < 20 should be skipped."""
        short_kde = (
            b"\xdd"
            b"\x0a"              # Length only 10
            b"\x00\x0f\xac\x04"
            + b"\xaa" * 6
        )
        result = capturer._extract_pmkid(short_kde)
        assert result is None


class TestPacketHandler:
    def test_eapol_frame_added(self, capturer):
        """EAPOL from target BSSID should be recorded."""
        pkt = _make_eapol_packet()
        capturer.packet_handler(pkt)
        assert len(capturer.eapol_frames) == 1

    def test_wrong_bssid_ignored(self, capturer):
        """EAPOL from a different BSSID should be ignored."""
        pkt = _make_eapol_packet(
            addr1="99:99:99:99:99:99",
            addr2="99:99:99:99:99:99",
            addr3="99:99:99:99:99:99",
        )
        capturer.packet_handler(pkt)
        assert len(capturer.eapol_frames) == 0

    def test_non_eapol_ignored(self, capturer):
        """Non-EAPOL packets should be skipped."""
        pkt = MagicMock()
        pkt.haslayer = MagicMock(return_value=False)
        capturer.packet_handler(pkt)
        assert len(capturer.eapol_frames) == 0

    def test_pmkid_extracted_from_eapol(self, capturer):
        """Full pipeline: EAPOL with PMKID KDE should set capturer.pmkid."""
        pmkid_hex = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        key_data = _build_pmkid_kde(pmkid_hex)
        eapol_raw = _build_eapol_key_data(key_data)

        pkt = _make_eapol_packet(
            addr1="11:22:33:44:55:66",
            addr2=TARGET_BSSID,
            addr3=TARGET_BSSID,
            eapol_raw=eapol_raw,
        )
        capturer.packet_handler(pkt)
        assert capturer.pmkid == pmkid_hex
        assert capturer.capture_complete is True
        assert capturer._stop_event.is_set()

    def test_eapol_without_pmkid_no_completion(self, capturer):
        """EAPOL from AP without PMKID should not complete capture."""
        pkt = _make_eapol_packet(
            addr2=TARGET_BSSID,
            eapol_raw=b"\x00" * 50,
        )
        capturer.packet_handler(pkt)
        assert capturer.pmkid is None
        assert capturer.capture_complete is False

    def test_non_ap_eapol_skips_extraction(self, capturer):
        """EAPOL where src != BSSID should be recorded but not parsed for PMKID."""
        pkt = _make_eapol_packet(
            addr1=TARGET_BSSID,
            addr2="11:22:33:44:55:66",
            addr3=TARGET_BSSID,
        )
        capturer.packet_handler(pkt)
        assert len(capturer.eapol_frames) == 1
        assert capturer.pmkid is None


class TestSendAssociation:
    @patch("pmkid_capture.sendp")
    @patch("pmkid_capture.time.sleep")
    def test_sends_frames(self, mock_sleep, mock_sendp, capturer):
        """Association should send auth + assoc frames."""
        capturer._send_association()
        assert mock_sendp.call_count == 2
        mock_sleep.assert_called_once_with(0.1)

    @patch("pmkid_capture.sendp")
    @patch("pmkid_capture.time.sleep")
    def test_uses_client_mac(self, mock_sleep, mock_sendp, capturer_with_client):
        """Should use the configured client MAC when set."""
        capturer_with_client._send_association()
        assert mock_sendp.call_count == 2

    @patch("pmkid_capture.sendp", side_effect=Exception("send failed"))
    @patch("pmkid_capture.time.sleep")
    def test_handles_send_error(self, mock_sleep, mock_sendp, capturer):
        """Errors during frame sending should be caught, not raised."""
        capturer._send_association()  # Should not raise


class TestSaveCapture:
    def test_save_with_pmkid(self, capturer, tmp_path):
        """Should save a .22000 file with hashcat-compatible format."""
        capturer.pmkid = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        capturer.essid = "TestNetwork"
        filepath = capturer.save_capture()
        assert filepath is not None
        assert filepath.endswith(".22000")
        assert os.path.isfile(filepath)

        with open(filepath, "r") as f:
            content = f.read().strip()

        assert content.startswith("WPA*02*")
        parts = content.split("*")
        assert parts[0] == "WPA"
        assert parts[1] == "02"
        assert parts[2] == "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        # AP MAC (lowercase, no colons)
        assert parts[3] == "aabbccddeeff"
        # STA MAC (default CC:CC:CC:CC:CC:CC lowercase, no colons)
        assert parts[4] == "cccccccccccc"
        # ESSID hex
        assert parts[5] == "TestNetwork".encode("utf-8").hex()

    def test_save_with_client_mac(self, capturer_with_client, tmp_path):
        """Should use the configured client MAC in the hashcat output."""
        capturer_with_client.pmkid = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        capturer_with_client.essid = "Net"
        filepath = capturer_with_client.save_capture()
        assert filepath is not None

        with open(filepath, "r") as f:
            content = f.read().strip()

        parts = content.split("*")
        assert parts[4] == CLIENT_MAC.replace(":", "").lower()

    def test_save_no_pmkid(self, capturer):
        """Should return None when no PMKID was captured."""
        result = capturer.save_capture()
        assert result is None

    def test_save_empty_essid(self, capturer, tmp_path):
        """Should handle empty/missing ESSID gracefully."""
        capturer.pmkid = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        capturer.essid = None
        filepath = capturer.save_capture()
        assert filepath is not None

        with open(filepath, "r") as f:
            content = f.read().strip()

        parts = content.split("*")
        # Empty ESSID -> empty hex
        assert parts[5] == ""

    @patch("pmkid_capture.wrpcap")
    def test_save_also_writes_pcap(self, mock_wrpcap, capturer, tmp_path):
        """When EAPOL frames exist, a .pcap should also be written."""
        capturer.pmkid = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        capturer.eapol_frames = [MagicMock()]
        filepath = capturer.save_capture()
        assert filepath is not None
        mock_wrpcap.assert_called_once()


class TestGetStatus:
    def test_status_dict(self, capturer):
        capturer._start_time = time.time()
        status = capturer.get_status()
        assert status["target_bssid"] == TARGET_BSSID
        assert status["client_mac"] is None
        assert status["pmkid"] is None
        assert status["capture_complete"] is False
        assert status["frames_captured"] == 0
        assert "elapsed_time" in status

    def test_status_after_capture(self, capturer):
        capturer._start_time = time.time() - 10
        capturer.pmkid = "deadbeef" * 4
        capturer.capture_complete = True
        capturer.eapol_frames = [MagicMock(), MagicMock()]
        status = capturer.get_status()
        assert status["pmkid"] == "deadbeef" * 4
        assert status["capture_complete"] is True
        assert status["frames_captured"] == 2
        assert status["elapsed_time"] >= 10

    def test_status_no_start_time(self, capturer):
        """Elapsed should be 0 if capture hasn't started."""
        status = capturer.get_status()
        assert status["elapsed_time"] == 0


class TestStart:
    @patch("pmkid_capture.sniff")
    def test_start_returns_bool(self, mock_sniff, capturer):
        mock_sniff.return_value = None
        result = capturer.start()
        assert isinstance(result, bool)

    @patch("pmkid_capture.sniff")
    def test_start_creates_output_dir(self, mock_sniff, capturer, tmp_path):
        mock_sniff.return_value = None
        capturer.start()
        assert os.path.isdir(capturer.output_dir)

    @patch("pmkid_capture.sniff")
    @patch("pmkid_capture.subprocess.run")
    def test_start_sets_channel(self, mock_run, mock_sniff, mock_interface, tmp_path):
        c = PMKIDCapture(
            interface=mock_interface,
            target_bssid=TARGET_BSSID,
            channel=11,
            output_dir=str(tmp_path),
        )
        c.start()
        mock_run.assert_called()

    @patch("pmkid_capture.sniff")
    def test_start_false_without_pmkid(self, mock_sniff, capturer):
        mock_sniff.return_value = None
        result = capturer.start()
        assert result is False

    @patch("pmkid_capture.sniff")
    def test_start_true_with_pmkid(self, mock_sniff, capturer):
        def side_effect(**kwargs):
            capturer.capture_complete = True
            capturer.pmkid = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        mock_sniff.side_effect = side_effect
        result = capturer.start()
        assert result is True


class TestCLI:
    def test_cli_required_args(self):
        """CLI should require -i and -b arguments."""
        from pmkid_capture import main
        with patch("sys.argv", ["pmkid_capture", "-i", "wlan0mon", "-b", TARGET_BSSID]):
            with patch("pmkid_capture.require_root"):
                with patch("pmkid_capture.check_monitor_mode", return_value=True):
                    with patch("pmkid_capture.validate_mac", return_value=True):
                        with patch.object(PMKIDCapture, "start", return_value=False):
                            with patch.object(PMKIDCapture, "save_capture", return_value=None):
                                with pytest.raises(SystemExit) as exc_info:
                                    main()
                                assert exc_info.value.code == 1

    def test_cli_all_args(self):
        """CLI should accept all optional arguments."""
        from pmkid_capture import main
        args = [
            "pmkid_capture",
            "-i", "wlan0mon",
            "-b", TARGET_BSSID,
            "-ch", "6",
            "-o", "/tmp/out",
            "-t", "120",
            "--client-mac", CLIENT_MAC,
            "-v",
        ]
        with patch("sys.argv", args):
            with patch("pmkid_capture.require_root"):
                with patch("pmkid_capture.check_monitor_mode", return_value=True):
                    with patch("pmkid_capture.validate_mac", return_value=True):
                        with patch.object(PMKIDCapture, "start", return_value=True):
                            with patch.object(PMKIDCapture, "save_capture",
                                              return_value="/tmp/out/pmkid.22000"):
                                with pytest.raises(SystemExit) as exc_info:
                                    main()
                                assert exc_info.value.code == 0

    def test_cli_invalid_bssid(self):
        """CLI should exit with code 1 for invalid BSSID."""
        from pmkid_capture import main
        with patch("sys.argv", ["pmkid_capture", "-i", "wlan0mon", "-b", "invalid"]):
            with patch("pmkid_capture.require_root"):
                with patch("pmkid_capture.validate_mac", return_value=False):
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    assert exc_info.value.code == 1

    def test_cli_invalid_client_mac(self):
        """CLI should exit with code 1 for invalid client MAC."""
        from pmkid_capture import main
        with patch("sys.argv", ["pmkid_capture", "-i", "wlan0mon",
                                 "-b", TARGET_BSSID, "--client-mac", "bad"]):
            with patch("pmkid_capture.require_root"):
                with patch("pmkid_capture.validate_mac", side_effect=[True, False]):
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    assert exc_info.value.code == 1


class TestMACValidation:
    """Verify that the module uses validate_mac from utils."""

    def test_valid_mac(self):
        from utils import validate_mac
        assert validate_mac("AA:BB:CC:DD:EE:FF") is True
        assert validate_mac("aa:bb:cc:dd:ee:ff") is True
        assert validate_mac("00:00:00:00:00:00") is True

    def test_invalid_mac(self):
        from utils import validate_mac
        assert validate_mac("not-a-mac") is False
        assert validate_mac("") is False
        assert validate_mac("AA:BB:CC:DD:EE") is False
        assert validate_mac("GG:HH:II:JJ:KK:LL") is False
