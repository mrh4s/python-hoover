"""Tests for dragonblood.py — WPA3 SAE Dragonblood testing module."""

import json
import os
import struct
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
from scapy.layers.dot11 import Dot11, Dot11Auth, Dot11Elt  # noqa: E402

from dragonblood import (  # noqa: E402
    AKM_PSK,
    AKM_SAE,
    ATTACK_MODES,
    AUTH_ALGO_OPEN,
    AUTH_ALGO_SAE,
    MANDATORY_GROUP,
    UNSUPPORTED_GROUP,
    DragonbloodAttack,
    main,
)

TARGET_BSSID = "AA:BB:CC:DD:EE:FF"
CLIENT_MAC = "11:22:33:44:55:66"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def attack(mock_interface, tmp_path):
    return DragonbloodAttack(
        interface=mock_interface,
        target_bssid=TARGET_BSSID,
        output_dir=str(tmp_path / "captures"),
        timeout=120,
    )


def _make_sae_auth_packet(status=0, seqnum=1, algo=AUTH_ALGO_SAE, src_mac="aa:bb:cc:dd:ee:ff"):
    """Create a mock packet carrying a Dot11Auth layer."""
    pkt = MagicMock()

    auth_layer = MagicMock()
    auth_layer.algo = algo
    auth_layer.status = status
    auth_layer.seqnum = seqnum

    dot11_layer = MagicMock()
    dot11_layer.addr2 = src_mac

    layers_present = {Dot11Auth, Dot11}
    pkt.haslayer = lambda cls: cls in layers_present

    def getitem(self, cls):
        if cls is Dot11Auth:
            return auth_layer
        if cls is Dot11:
            return dot11_layer
        return MagicMock()

    pkt.__getitem__ = getitem

    return pkt


def _make_non_auth_packet():
    """Create a mock packet without a Dot11Auth layer."""
    pkt = MagicMock()
    pkt.haslayer = lambda cls: False
    return pkt


# ---------------------------------------------------------------------------
# 1-2. __init__
# ---------------------------------------------------------------------------


class TestDragonbloodAttackInit:
    def test_init_defaults(self, mock_interface):
        a = DragonbloodAttack(interface=mock_interface, target_bssid=TARGET_BSSID)
        assert a.interface == mock_interface
        assert a.target_bssid == TARGET_BSSID
        assert a.channel is None
        assert a.attack_mode == "downgrade"
        assert a.timeout == 120
        assert a.output_dir == "captures"
        assert a.client_mac is None
        assert a.captured_sae_frames == []
        assert a.results == {}
        assert a._running is False

    def test_init_custom_params(self, mock_interface):
        a = DragonbloodAttack(
            interface=mock_interface,
            target_bssid=TARGET_BSSID.lower(),
            channel=6,
            attack_mode="timing",
            timeout=300,
            output_dir="/tmp/dragon_caps",
            client_mac=CLIENT_MAC.lower(),
        )
        assert a.target_bssid == TARGET_BSSID
        assert a.channel == 6
        assert a.attack_mode == "timing"
        assert a.timeout == 300
        assert a.output_dir == "/tmp/dragon_caps"
        assert a.client_mac == CLIENT_MAC


# ---------------------------------------------------------------------------
# 3. _build_sae_commit
# ---------------------------------------------------------------------------


class TestBuildSaeCommit:
    def test_build_sae_commit_frame_structure(self, attack):
        scalar = b"\x11" * 32
        element = b"\x22" * 64
        body = attack._build_sae_commit(19, scalar, element)

        assert isinstance(body, bytes)
        assert len(body) == 2 + 32 + 64

        group_id = struct.unpack("<H", body[0:2])[0]
        assert group_id == 19
        assert body[2:34] == scalar
        assert body[34:98] == element


# ---------------------------------------------------------------------------
# 4. _build_sae_confirm
# ---------------------------------------------------------------------------


class TestBuildSaeConfirm:
    def test_build_sae_confirm_frame_structure(self, attack):
        confirm = b"\x55" * 32
        body = attack._build_sae_confirm(1, confirm)

        assert isinstance(body, bytes)
        assert len(body) == 2 + 32

        send_confirm = struct.unpack("<H", body[0:2])[0]
        assert send_confirm == 1
        assert body[2:34] == confirm


# ---------------------------------------------------------------------------
# 5-6. _build_downgrade_beacon
# ---------------------------------------------------------------------------


class TestBuildDowngradeBeacon:
    def _rsn_info_from_calls(self):
        """Find the info= bytes passed to the RSN (ID=48) Dot11Elt call."""
        for c in Dot11Elt.call_args_list:
            if c.kwargs.get("ID") == 48:
                return c.kwargs.get("info")
        return None

    def test_build_downgrade_beacon_has_no_sae_akm(self, attack):
        Dot11Elt.reset_mock()
        attack._build_downgrade_beacon("TestNet")
        rsn_info = self._rsn_info_from_calls()
        assert rsn_info is not None
        assert AKM_SAE not in rsn_info

    def test_build_downgrade_beacon_has_psk_akm(self, attack):
        Dot11Elt.reset_mock()
        attack._build_downgrade_beacon("TestNet")
        rsn_info = self._rsn_info_from_calls()
        assert rsn_info is not None
        assert AKM_PSK in rsn_info


# ---------------------------------------------------------------------------
# 7-8. packet_handler
# ---------------------------------------------------------------------------


class TestPacketHandler:
    def test_packet_handler_captures_sae_auth(self, attack):
        pkt = _make_sae_auth_packet(
            status=0, seqnum=1, algo=AUTH_ALGO_SAE, src_mac="aa:bb:cc:dd:ee:ff"
        )
        attack.packet_handler(pkt)

        assert len(attack.captured_sae_frames) == 1
        frame = attack.captured_sae_frames[0]
        assert frame["src_mac"] == "aa:bb:cc:dd:ee:ff"
        assert frame["seqnum"] == 1
        assert frame["status"] == 0

    def test_packet_handler_ignores_non_sae(self, attack):
        # Dot11Auth present, but algo is open-system (not SAE)
        open_auth_pkt = _make_sae_auth_packet(algo=AUTH_ALGO_OPEN)
        attack.packet_handler(open_auth_pkt)
        assert len(attack.captured_sae_frames) == 0

        # No Dot11Auth layer at all
        non_auth_pkt = _make_non_auth_packet()
        attack.packet_handler(non_auth_pkt)
        assert len(attack.captured_sae_frames) == 0


# ---------------------------------------------------------------------------
# 9. _measure_commit_timing
# ---------------------------------------------------------------------------


class TestMeasureCommitTiming:
    @patch("dragonblood.sniff")
    @patch("dragonblood.sendp")
    def test_measure_commit_timing_returns_floats(self, mock_sendp, mock_sniff, attack):
        mock_sniff.return_value = []
        timings = attack._measure_commit_timing(MANDATORY_GROUP, iterations=5)

        assert isinstance(timings, list)
        assert len(timings) == 5
        for t in timings:
            assert isinstance(t, float)
            assert t >= 0.0

        assert mock_sendp.call_count == 5
        assert mock_sniff.call_count == 5
        assert attack.results["timing"][MANDATORY_GROUP] == timings


# ---------------------------------------------------------------------------
# 10. _test_group_negotiation
# ---------------------------------------------------------------------------


class TestGroupNegotiation:
    @patch("dragonblood.sniff")
    @patch("dragonblood.sendp")
    def test_test_group_negotiation_parses_status_codes(self, mock_sendp, mock_sniff, attack):
        accepted_pkt = _make_sae_auth_packet(status=0)
        rejected_pkt = _make_sae_auth_packet(status=UNSUPPORTED_GROUP)

        mock_sniff.side_effect = [
            [accepted_pkt],  # group 19 -> accepted
            [rejected_pkt],  # group 20 -> rejected (unsupported group)
        ]

        results = attack._test_group_negotiation([19, 20])

        assert results[19]["accepted"] is True
        assert results[19]["status"] == 0
        assert results[20]["accepted"] is False
        assert results[20]["status"] == UNSUPPORTED_GROUP
        assert attack.results["group_negotiation"] == results


# ---------------------------------------------------------------------------
# 11. save_results
# ---------------------------------------------------------------------------


class TestSaveResults:
    def test_save_results_creates_json(self, attack):
        attack.results = {"mode": "downgrade", "target_bssid": TARGET_BSSID, "data": {}}
        filepath = attack.save_results()

        assert filepath is not None
        assert os.path.exists(filepath)
        with open(filepath, encoding="utf-8") as f:
            saved = json.load(f)
        assert saved["mode"] == "downgrade"
        assert saved["target_bssid"] == TARGET_BSSID

    def test_save_results_no_results_returns_none(self, attack):
        assert attack.results == {}
        assert attack.save_results() is None


# ---------------------------------------------------------------------------
# 12. get_status
# ---------------------------------------------------------------------------


class TestGetStatus:
    def test_get_status_initial(self, attack):
        status = attack.get_status()

        assert status["running"] is False
        assert status["interface"] == attack.interface
        assert status["target_bssid"] == TARGET_BSSID
        assert status["attack_mode"] == "downgrade"
        assert status["channel"] is None
        assert status["captured_sae_frames"] == 0
        assert status["timeout"] == 120


# ---------------------------------------------------------------------------
# 13-14. CLI
# ---------------------------------------------------------------------------


class TestCLI:
    def test_cli_required_args(self):
        """CLI should require -i and -b arguments."""
        with patch("sys.argv", ["dragonblood"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    def test_cli_mode_choices(self):
        """CLI should reject an invalid attack mode."""
        args = [
            "dragonblood",
            "-i",
            "wlan0mon",
            "-b",
            TARGET_BSSID,
            "-m",
            "not-a-real-mode",
        ]
        with patch("sys.argv", args):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    def test_cli_valid_mode_accepted(self):
        """Sanity check: every documented mode is a valid CLI choice."""
        assert set(ATTACK_MODES) == {"downgrade", "timing", "group-test", "clogging"}

        args = [
            "dragonblood",
            "-i",
            "wlan0mon",
            "-b",
            TARGET_BSSID,
            "-m",
            "group-test",
        ]
        with patch("sys.argv", args):
            with patch("dragonblood.require_root"):
                with patch.object(DragonbloodAttack, "start", return_value={}):
                    with patch.object(DragonbloodAttack, "save_results", return_value=None):
                        with pytest.raises(SystemExit) as exc_info:
                            main()
                        assert exc_info.value.code == 0
