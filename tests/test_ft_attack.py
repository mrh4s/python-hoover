"""Tests for ft_attack.py -- 802.11r Fast BSS Transition vulnerability detection."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.utils", MagicMock())

# Import mocked classes as production code sees them
from scapy.layers.dot11 import (  # noqa: E402
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11ReassoReq,
    Dot11ReassoResp,
)

from ft_attack import (  # noqa: E402
    FT_ACTION_CATEGORY,
    FT_ACTION_REQUEST,
    FT_ACTION_RESPONSE,
    FT_AUTH_ALG,
    FTIE_ID,
    MDIE_ID,
    TEST_MODES,
    FTAttack,
    main,
)

BSSID = "AA:BB:CC:DD:EE:FF"
CLIENT = "11:22:33:44:55:66"


def _build_mdie(mdid: int = 0x1234, ft_cap_policy: int = 0x01) -> bytes:
    """Build a raw Mobility Domain IE body (3 bytes)."""
    return mdid.to_bytes(2, "little") + bytes([ft_cap_policy])


def _build_ftie(
    mic: bytes = b"\x00" * 16,
    anonce: bytes = b"\xaa" * 32,
    snonce: bytes = b"\xbb" * 32,
    r0kh_id: bytes = b"",
    r1kh_id: bytes = b"",
) -> bytes:
    """Build a raw FTIE body: MIC Control(2) + MIC(16) + ANonce(32) + SNonce(32)
    + optional sub-elements."""
    body = bytearray()
    body += b"\x00\x00"  # MIC Control (2 bytes)
    body += mic[:16].ljust(16, b"\x00")
    body += anonce[:32].ljust(32, b"\x00")
    body += snonce[:32].ljust(32, b"\x00")

    if r0kh_id:
        body += bytes([3, len(r0kh_id)]) + r0kh_id  # sub-element ID 3
    if r1kh_id:
        body += bytes([1, len(r1kh_id)]) + r1kh_id  # sub-element ID 1

    return bytes(body)


class _FakeElt:
    """Minimal stand-in for Dot11Elt with chained payloads."""

    def __init__(self, tag_id, info, next_elt=None):
        self.ID = tag_id
        self.info = info
        self._next = next_elt
        self.payload = self

    def getlayer(self, cls):
        return self._next


def _make_beacon_packet(bssid: str = BSSID, mdie_data: bytes = None, ftie_data: bytes = None):
    """Create a mock Beacon packet with optional MDIE and FTIE."""
    pkt = MagicMock()

    dot11_layer = MagicMock()
    dot11_layer.addr1 = "ff:ff:ff:ff:ff:ff"
    dot11_layer.addr2 = bssid
    dot11_layer.addr3 = bssid

    # Build the Dot11Elt chain
    elts = []
    if ftie_data is not None:
        elts.append(_FakeElt(FTIE_ID, ftie_data))
    if mdie_data is not None:
        elts.append(_FakeElt(MDIE_ID, mdie_data))

    # Chain them
    if len(elts) > 1:
        for i in range(len(elts) - 1):
            elts[i]._next = elts[i + 1]
    first_elt = elts[0] if elts else None

    layers_present = {Dot11, Dot11Beacon}
    if first_elt is not None:
        layers_present.add(Dot11Elt)

    pkt.haslayer = lambda cls: cls in layers_present

    def getitem(self, cls):
        if cls is Dot11:
            return dot11_layer
        return MagicMock()

    pkt.__getitem__ = getitem

    pkt.getlayer = lambda cls: first_elt if cls is Dot11Elt else None

    return pkt


def _make_reassoc_resp_packet(bssid: str = BSSID, client: str = CLIENT, ftie_data: bytes = None):
    """Create a mock FT Reassociation Response packet."""
    pkt = MagicMock()

    dot11_layer = MagicMock()
    dot11_layer.addr1 = client
    dot11_layer.addr2 = bssid
    dot11_layer.addr3 = bssid

    first_elt = None
    if ftie_data is not None:
        first_elt = _FakeElt(FTIE_ID, ftie_data)

    layers_present = {Dot11, Dot11ReassoResp}
    if first_elt is not None:
        layers_present.add(Dot11Elt)

    pkt.haslayer = lambda cls: cls in layers_present

    def getitem(self, cls):
        if cls is Dot11:
            return dot11_layer
        return MagicMock()

    pkt.__getitem__ = getitem

    pkt.getlayer = lambda cls: first_elt if cls is Dot11Elt else None

    return pkt


def _make_reassoc_req_packet(bssid: str = BSSID, client: str = CLIENT, ftie_data: bytes = None):
    """Create a mock FT Reassociation Request packet."""
    pkt = MagicMock()

    dot11_layer = MagicMock()
    dot11_layer.addr1 = bssid
    dot11_layer.addr2 = client
    dot11_layer.addr3 = bssid

    first_elt = None
    if ftie_data is not None:
        first_elt = _FakeElt(FTIE_ID, ftie_data)

    layers_present = {Dot11, Dot11ReassoReq}
    if first_elt is not None:
        layers_present.add(Dot11Elt)

    pkt.haslayer = lambda cls: cls in layers_present

    def getitem(self, cls):
        if cls is Dot11:
            return dot11_layer
        return MagicMock()

    pkt.__getitem__ = getitem

    pkt.getlayer = lambda cls: first_elt if cls is Dot11Elt else None

    return pkt


class _FakePayload:
    """Stand-in for a Dot11 payload that supports bytes() conversion."""

    def __init__(self, data: bytes):
        self._data = data

    def __bytes__(self):
        return self._data

    def __bool__(self):
        return bool(self._data)


def _make_action_packet(
    bssid: str = BSSID,
    client: str = CLIENT,
    category: int = FT_ACTION_CATEGORY,
    action_code: int = FT_ACTION_REQUEST,
):
    """Create a mock FT Action frame."""
    pkt = MagicMock()

    dot11_layer = MagicMock()
    dot11_layer.addr1 = bssid
    dot11_layer.addr2 = client
    dot11_layer.addr3 = bssid
    dot11_layer.type = 0
    dot11_layer.subtype = 13

    payload_bytes = bytes([category, action_code])
    dot11_layer.payload = _FakePayload(payload_bytes)

    layers_present = {Dot11}

    pkt.haslayer = lambda cls: cls in layers_present

    def getitem(self, cls):
        if cls is Dot11:
            return dot11_layer
        return MagicMock()

    pkt.__getitem__ = getitem

    pkt.getlayer = lambda cls: None

    return pkt


def _make_non_dot11_packet():
    """Create a packet with no Dot11 layer."""
    pkt = MagicMock()
    pkt.haslayer = lambda cls: False
    return pkt


@pytest.fixture
def attacker(mock_interface, tmp_path):
    return FTAttack(
        interface=mock_interface,
        target_bssid=BSSID,
        target_client=CLIENT,
        channel=6,
        timeout=180,
        output_dir=str(tmp_path / "captures"),
        test_mode="reassoc",
    )


# ---------------------------------------------------------------------------
# 1. Init defaults
# ---------------------------------------------------------------------------
class TestInit:
    def test_init_defaults(self, mock_interface):
        a = FTAttack(interface=mock_interface, target_bssid=BSSID)
        assert a.interface == mock_interface
        assert a.target_bssid == BSSID
        assert a.target_client is None
        assert a.channel is None
        assert a.timeout == 180
        assert a.output_dir == "captures"
        assert a.test_mode == "reassoc"
        assert a.detect_only is False
        assert a.vulnerable is False
        assert a.findings == []
        assert a.captured_frames == []
        assert a.ft_capable_aps == {}

    def test_init_with_all_args(self, mock_interface, tmp_path):
        a = FTAttack(
            interface=mock_interface,
            target_bssid=BSSID,
            channel=36,
            target_client=CLIENT,
            timeout=60,
            output_dir=str(tmp_path),
            test_mode="over-ds",
            detect_only=True,
        )
        assert a.channel == 36
        assert a.target_client == CLIENT
        assert a.timeout == 60
        assert a.test_mode == "over-ds"
        assert a.detect_only is True

    def test_bssid_uppercased(self, mock_interface):
        a = FTAttack(interface=mock_interface, target_bssid="aa:bb:cc:dd:ee:ff")
        assert a.target_bssid == "AA:BB:CC:DD:EE:FF"

    def test_client_uppercased(self, mock_interface):
        a = FTAttack(
            interface=mock_interface, target_bssid=BSSID, target_client="11:22:33:44:55:66"
        )
        assert a.target_client == "11:22:33:44:55:66".upper()


# ---------------------------------------------------------------------------
# 2. MDIE parsing
# ---------------------------------------------------------------------------
class TestParseMDIE:
    def test_parse_mdie_valid(self, attacker):
        data = _build_mdie(mdid=0xABCD, ft_cap_policy=0x03)
        result = attacker._parse_mdie(data)
        assert result["mdid"] == 0xABCD
        assert result["ft_cap_policy"] == 0x03

    def test_parse_mdie_too_short(self, attacker):
        result = attacker._parse_mdie(b"\x01\x02")
        assert result["mdid"] == 0
        assert result["ft_cap_policy"] == 0

    def test_parse_mdie_empty(self, attacker):
        result = attacker._parse_mdie(b"")
        assert result["mdid"] == 0

    def test_parse_mdie_none(self, attacker):
        result = attacker._parse_mdie(None)
        assert result["mdid"] == 0


# ---------------------------------------------------------------------------
# 3. FTIE parsing
# ---------------------------------------------------------------------------
class TestParseFTIE:
    def test_parse_ftie_valid(self, attacker):
        mic = b"\x11" * 16
        anonce = b"\xaa" * 32
        snonce = b"\xbb" * 32
        data = _build_ftie(mic=mic, anonce=anonce, snonce=snonce)
        result = attacker._parse_ftie(data)
        assert result["mic"] == mic
        assert result["anonce"] == anonce
        assert result["snonce"] == snonce

    def test_parse_ftie_with_subelements(self, attacker):
        r0kh = b"r0kh.example.com"
        r1kh = b"\xcc" * 6
        data = _build_ftie(r0kh_id=r0kh, r1kh_id=r1kh)
        result = attacker._parse_ftie(data)
        assert result["r0kh_id"] == r0kh
        assert result["r1kh_id"] == r1kh

    def test_parse_ftie_too_short(self, attacker):
        result = attacker._parse_ftie(b"\x00" * 10)
        assert result["mic"] == b""
        assert result["anonce"] == b""
        assert result["snonce"] == b""

    def test_parse_ftie_empty(self, attacker):
        result = attacker._parse_ftie(b"")
        assert result["anonce"] == b""

    def test_parse_ftie_none(self, attacker):
        result = attacker._parse_ftie(None)
        assert result["anonce"] == b""


# ---------------------------------------------------------------------------
# 4. FT support detection
# ---------------------------------------------------------------------------
class TestDetectFTSupport:
    def test_detect_ft_support_from_beacon(self, attacker):
        mdie = _build_mdie(mdid=0x1234)
        pkt = _make_beacon_packet(bssid=BSSID, mdie_data=mdie)
        attacker._detect_ft_support(pkt)
        assert BSSID in attacker.ft_capable_aps
        assert attacker.ft_capable_aps[BSSID]["mdid"] == 0x1234

    def test_detect_ft_support_ignores_non_target(self, attacker):
        mdie = _build_mdie()
        pkt = _make_beacon_packet(bssid="99:99:99:99:99:99", mdie_data=mdie)
        attacker._detect_ft_support(pkt)
        assert len(attacker.ft_capable_aps) == 0

    def test_detect_ft_support_with_ftie(self, attacker):
        mdie = _build_mdie()
        ftie = _build_ftie(anonce=b"\xdd" * 32)
        pkt = _make_beacon_packet(bssid=BSSID, mdie_data=mdie, ftie_data=ftie)
        attacker._detect_ft_support(pkt)
        assert "ftie" in attacker.ft_capable_aps[BSSID]


# ---------------------------------------------------------------------------
# 5. Reassociation tracking
# ---------------------------------------------------------------------------
class TestTrackFTReassociation:
    def test_track_reassoc_response_anonce(self, attacker):
        anonce = b"\xaa" * 32
        ftie = _build_ftie(anonce=anonce)
        pkt = _make_reassoc_resp_packet(ftie_data=ftie)
        attacker._track_ft_reassociation(pkt)
        key = (BSSID, CLIENT)
        assert key in attacker._reassoc_anonces
        assert len(attacker._reassoc_anonces[key]) == 1
        assert attacker._reassoc_anonces[key][0] == anonce

    def test_track_reassoc_request_does_not_add_anonce(self, attacker):
        ftie = _build_ftie(anonce=b"\xbb" * 32)
        pkt = _make_reassoc_req_packet(ftie_data=ftie)
        attacker._track_ft_reassociation(pkt)
        # Requests do not contribute ANonces for replay detection
        assert len(attacker._reassoc_anonces) == 0

    def test_track_ignores_wrong_bssid(self, attacker):
        ftie = _build_ftie()
        pkt = _make_reassoc_resp_packet(bssid="99:99:99:99:99:99", ftie_data=ftie)
        attacker._track_ft_reassociation(pkt)
        assert len(attacker._reassoc_anonces) == 0


# ---------------------------------------------------------------------------
# 6. Key reinstallation detection
# ---------------------------------------------------------------------------
class TestDetectKeyReinstallation:
    def test_detect_reinstallation_with_replayed_anonce(self, attacker):
        anonce = b"\xaa" * 32
        ftie = _build_ftie(anonce=anonce)
        # Two reassoc responses with same ANonce
        pkt1 = _make_reassoc_resp_packet(ftie_data=ftie)
        pkt2 = _make_reassoc_resp_packet(ftie_data=ftie)
        attacker._track_ft_reassociation(pkt1)
        attacker._track_ft_reassociation(pkt2)

        assert attacker._detect_key_reinstallation() is True
        assert attacker.vulnerable is True
        assert len(attacker.findings) >= 1
        assert attacker.findings[0]["cve"] == "CVE-2017-13082"

    def test_no_false_positive_on_different_anonces(self, attacker):
        ftie1 = _build_ftie(anonce=b"\xaa" * 32)
        ftie2 = _build_ftie(anonce=b"\xbb" * 32)
        pkt1 = _make_reassoc_resp_packet(ftie_data=ftie1)
        pkt2 = _make_reassoc_resp_packet(ftie_data=ftie2)
        attacker._track_ft_reassociation(pkt1)
        attacker._track_ft_reassociation(pkt2)

        assert attacker._detect_key_reinstallation() is False
        assert attacker.vulnerable is False
        assert attacker.findings == []

    def test_no_reinstallation_with_single_response(self, attacker):
        ftie = _build_ftie(anonce=b"\xaa" * 32)
        pkt = _make_reassoc_resp_packet(ftie_data=ftie)
        attacker._track_ft_reassociation(pkt)

        assert attacker._detect_key_reinstallation() is False


# ---------------------------------------------------------------------------
# 7. Packet handler filtering
# ---------------------------------------------------------------------------
class TestPacketHandler:
    def test_packet_handler_ignores_non_dot11(self, attacker):
        pkt = _make_non_dot11_packet()
        attacker.packet_handler(pkt)
        assert attacker.captured_frames == []

    def test_packet_handler_filters_by_bssid(self, attacker):
        """A packet with no matching BSSID in addr1-3 is ignored."""
        pkt = MagicMock()
        dot11_layer = MagicMock()
        dot11_layer.addr1 = "99:99:99:99:99:99"
        dot11_layer.addr2 = "88:88:88:88:88:88"
        dot11_layer.addr3 = "77:77:77:77:77:77"
        pkt.haslayer = lambda cls: cls is Dot11
        pkt.__getitem__ = lambda self, cls: dot11_layer if cls is Dot11 else MagicMock()
        pkt.getlayer = lambda cls: None
        attacker.packet_handler(pkt)
        assert attacker.captured_frames == []

    def test_packet_handler_captures_matching_beacon(self, attacker):
        mdie = _build_mdie()
        pkt = _make_beacon_packet(bssid=BSSID, mdie_data=mdie)
        attacker.packet_handler(pkt)
        assert len(attacker.captured_frames) == 1


# ---------------------------------------------------------------------------
# 8. FT Action frames (over-DS)
# ---------------------------------------------------------------------------
class TestFTActionFrames:
    def test_check_ft_action_request(self, attacker):
        attacker.test_mode = "over-ds"
        pkt = _make_action_packet(action_code=FT_ACTION_REQUEST)
        attacker._check_ft_action_frames(pkt)
        key = (BSSID, CLIENT)
        assert key in attacker._ft_action_frames
        assert attacker._ft_action_frames[key][0]["action_type"] == "request"

    def test_check_ft_action_response(self, attacker):
        attacker.test_mode = "over-ds"
        pkt = _make_action_packet(action_code=FT_ACTION_RESPONSE)
        attacker._check_ft_action_frames(pkt)
        key = (BSSID, CLIENT)
        assert attacker._ft_action_frames[key][0]["action_type"] == "response"

    def test_ignores_non_ft_category(self, attacker):
        pkt = _make_action_packet(category=99)
        attacker._check_ft_action_frames(pkt)
        assert len(attacker._ft_action_frames) == 0


# ---------------------------------------------------------------------------
# 9. save_results
# ---------------------------------------------------------------------------
class TestSaveResults:
    def test_save_results_writes_json(self, attacker, tmp_path):
        mdie = _build_mdie()
        pkt = _make_beacon_packet(bssid=BSSID, mdie_data=mdie)
        attacker.packet_handler(pkt)
        attacker.findings.append({"type": "test_finding"})

        with patch("ft_attack.wrpcap"):
            filepath = attacker.save_results()

        assert filepath is not None
        assert os.path.exists(filepath)
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        assert data["target_bssid"] == BSSID
        assert data["findings"] == [{"type": "test_finding"}]

    def test_save_results_returns_none_when_empty(self, attacker):
        assert attacker.save_results() is None


# ---------------------------------------------------------------------------
# 10. get_status
# ---------------------------------------------------------------------------
class TestGetStatus:
    def test_get_status_initial(self, attacker):
        status = attacker.get_status()
        assert status["running"] is False
        assert status["interface"] == attacker.interface
        assert status["target_bssid"] == BSSID
        assert status["target_client"] == CLIENT
        assert status["mode"] == "reassoc"
        assert status["detect_only"] is False
        assert status["frames_captured"] == 0
        assert status["vulnerable"] is False
        assert status["findings_count"] == 0
        assert status["ft_capable_aps"] == 0
        assert "elapsed_seconds" in status
        assert status["timeout"] == 180


# ---------------------------------------------------------------------------
# 11. Test modes constant
# ---------------------------------------------------------------------------
class TestConstants:
    def test_test_modes(self):
        assert "reassoc" in TEST_MODES
        assert "pmk-r1" in TEST_MODES
        assert "over-ds" in TEST_MODES
        assert "all" in TEST_MODES

    def test_ie_ids(self):
        assert MDIE_ID == 54
        assert FTIE_ID == 55

    def test_ft_auth_alg(self):
        assert FT_AUTH_ALG == 2

    def test_ft_action_constants(self):
        assert FT_ACTION_CATEGORY == 6
        assert FT_ACTION_REQUEST == 1
        assert FT_ACTION_RESPONSE == 2


# ---------------------------------------------------------------------------
# 12-13. CLI behavior
# ---------------------------------------------------------------------------
class TestCLI:
    def test_cli_detect_only_flag(self, tmp_path):
        test_args = [
            "ft_attack.py",
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
            "ft_capable_aps": {},
            "frames_captured": 0,
            "mode": "reassoc",
        }
        with (
            patch.object(sys, "argv", test_args),
            patch("ft_attack.require_root"),
            patch("ft_attack.FTAttack.start", return_value=fake_results) as mock_start,
            patch("ft_attack.FTAttack.save_results", return_value=None),
            patch("ft_attack.sys.exit"),
        ):
            main()

        mock_start.assert_called_once()

    def test_cli_mode_choices(self):
        test_args = [
            "ft_attack.py",
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
        test_args = ["ft_attack.py"]
        with patch.object(sys, "argv", test_args):
            with pytest.raises(SystemExit):
                main()

    def test_cli_over_ds_mode(self, tmp_path):
        test_args = [
            "ft_attack.py",
            "-i",
            "wlan0mon",
            "-b",
            BSSID,
            "-m",
            "over-ds",
            "-t",
            "1",
        ]
        fake_results = {
            "vulnerable": False,
            "findings": [],
            "ft_capable_aps": {},
            "frames_captured": 0,
            "mode": "over-ds",
        }
        with (
            patch.object(sys, "argv", test_args),
            patch("ft_attack.require_root"),
            patch("ft_attack.FTAttack.start", return_value=fake_results),
            patch("ft_attack.FTAttack.save_results", return_value=None),
            patch("ft_attack.sys.exit"),
        ):
            main()

    def test_cli_all_mode(self, tmp_path):
        test_args = [
            "ft_attack.py",
            "-i",
            "wlan0mon",
            "-b",
            BSSID,
            "-m",
            "all",
            "-t",
            "1",
        ]
        fake_results = {
            "vulnerable": False,
            "findings": [],
            "ft_capable_aps": {},
            "frames_captured": 0,
            "mode": "all",
        }
        with (
            patch.object(sys, "argv", test_args),
            patch("ft_attack.require_root"),
            patch("ft_attack.FTAttack.start", return_value=fake_results),
            patch("ft_attack.FTAttack.save_results", return_value=None),
            patch("ft_attack.sys.exit"),
        ):
            main()
