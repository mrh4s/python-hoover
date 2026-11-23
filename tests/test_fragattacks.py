"""Tests for fragattacks.py -- FragAttacks vulnerability testing module."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing the module under test
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.layers.eap", MagicMock())
sys.modules.setdefault("scapy.layers.l2", MagicMock())
sys.modules.setdefault("scapy.layers.inet", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.packet", MagicMock())
sys.modules.setdefault("scapy.utils", MagicMock())

# Import mocked scapy classes as the production code sees them

from fragattacks import TEST_MODES, FragAttacks  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def attacker(mock_interface, tmp_path):
    """Create a FragAttacks instance with safe defaults for testing."""
    return FragAttacks(
        interface=mock_interface,
        target_bssid="aa:bb:cc:dd:ee:ff",
        target_client="11:22:33:44:55:66",
        channel=6,
        timeout=120,
        output_dir=str(tmp_path / "captures"),
        test_mode="aggregation",
    )


# ---------------------------------------------------------------------------
# 1. test_init_defaults
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_defaults(self, mock_interface, tmp_path):
        """Verify default parameters are set correctly."""
        fa = FragAttacks(
            interface=mock_interface,
            target_bssid="aa:bb:cc:dd:ee:ff",
            output_dir=str(tmp_path / "out"),
        )
        assert fa.interface == mock_interface
        assert fa.target_bssid == "aa:bb:cc:dd:ee:ff"
        assert fa.target_client is None
        assert fa.channel is None
        assert fa.timeout == 120
        assert fa.test_mode == "aggregation"
        assert fa._running is False
        assert fa.results == {}
        assert fa.responses == []


# ---------------------------------------------------------------------------
# 2-3. test_build_amsdu_*
# ---------------------------------------------------------------------------

class TestBuildAmsdu:
    def test_build_amsdu_single_subframe(self, attacker):
        """Verify A-MSDU structure with one subframe (DA+SA+Len+payload, padded)."""
        payload = b"\x08\x00TEST"
        result = attacker._build_amsdu_frame([
            ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", payload),
        ])

        # DA (6) + SA (6) + Length (2) + payload (6) = 20 bytes
        # Padded to next 4-byte boundary: 20 is already 4-aligned -> 20
        assert isinstance(result, bytes)
        # Check DA
        assert result[0:6] == bytes.fromhex("aabbccddeeff")
        # Check SA
        assert result[6:12] == bytes.fromhex("112233445566")
        # Check Length (big-endian)
        assert int.from_bytes(result[12:14], "big") == len(payload)
        # Check payload
        assert result[14:14 + len(payload)] == payload

    def test_build_amsdu_multiple_subframes(self, attacker):
        """Verify padding between subframes for 4-byte alignment."""
        payload1 = b"A" * 5   # 6+6+2+5=19 bytes, pad to 20
        payload2 = b"B" * 7   # 6+6+2+7=21 bytes, pad to 24

        result = attacker._build_amsdu_frame([
            ("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", payload1),
            ("11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff", payload2),
        ])

        # First subframe: 6+6+2+5 = 19, padded to 20
        # Second subframe: 6+6+2+7 = 21, padded to 24
        assert len(result) == 20 + 24

        # First subframe length field
        assert int.from_bytes(result[12:14], "big") == 5
        # Second subframe starts at offset 20
        assert int.from_bytes(result[20 + 12:20 + 14], "big") == 7


# ---------------------------------------------------------------------------
# 4-6. test_build_fragmented_frame_*
# ---------------------------------------------------------------------------

class _FakePacket:
    """Minimal packet stand-in that supports attribute setting and `/`."""

    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __truediv__(self, other):
        # Chaining (Dot11(...) / Raw(...)) just returns self.
        return self


class TestBuildFragmentedFrame:

    @patch("fragattacks.Raw", side_effect=lambda **kw: _FakePacket(**kw))
    @patch("fragattacks.Dot11", side_effect=lambda **kw: _FakePacket(**kw))
    def test_build_fragmented_frame_count(self, _mock_dot11, _mock_raw,
                                           attacker):
        """100-byte payload with 50-byte fragments -> 2 fragments."""
        payload = b"X" * 100
        fragments = attacker._build_fragmented_frame(payload, fragment_size=50)
        assert len(fragments) == 2

    @patch("fragattacks.Raw", side_effect=lambda **kw: _FakePacket(**kw))
    @patch("fragattacks.Dot11", side_effect=lambda **kw: _FakePacket(**kw))
    def test_build_fragmented_frame_sequence_numbers(self, _mock_dot11,
                                                      _mock_raw, attacker):
        """Verify SC field has correct fragment numbers."""
        attacker._sequence_number = 42
        payload = b"Z" * 100
        fragments = attacker._build_fragmented_frame(payload, fragment_size=50)

        # Both fragments should share the same sequence number (42)
        # SC = (seq_num << 4) | frag_num
        assert fragments[0].SC == (42 << 4) | 0  # frag 0
        assert fragments[1].SC == (42 << 4) | 1  # frag 1

    @patch("fragattacks.Raw", side_effect=lambda **kw: _FakePacket(**kw))
    @patch("fragattacks.Dot11", side_effect=lambda **kw: _FakePacket(**kw))
    def test_build_fragmented_frame_more_fragments_bit(self, _mock_dot11,
                                                        _mock_raw, attacker):
        """First fragment has MF set, last fragment does not."""
        payload = b"M" * 100
        fragments = attacker._build_fragmented_frame(payload, fragment_size=50)

        # First fragment: More Fragments bit (0x04) should be set
        assert (fragments[0].FCfield & 0x04) != 0
        # Last fragment: More Fragments bit should be clear
        assert (fragments[1].FCfield & 0x04) == 0


# ---------------------------------------------------------------------------
# 7-8. test_set_fragment_number / test_set_sequence_number
# ---------------------------------------------------------------------------

class TestSCFieldManipulation:
    def test_set_fragment_number(self, attacker):
        """Verify SC field manipulation for fragment number."""
        pkt = MagicMock()
        pkt.SC = 0
        pkt.FCfield = 0

        # Set fragment number 5 with MF
        result = attacker._set_fragment_number(pkt, 5, more_fragments=True)
        assert (result.SC & 0x0F) == 5
        assert (result.FCfield & 0x04) != 0

        # Set fragment number 0 without MF
        result.SC = result.SC  # keep seq
        result = attacker._set_fragment_number(result, 0, more_fragments=False)
        assert (result.SC & 0x0F) == 0
        assert (result.FCfield & 0x04) == 0

    def test_set_sequence_number(self, attacker):
        """Verify SC field manipulation for sequence number."""
        pkt = MagicMock()
        pkt.SC = 0
        pkt.FCfield = 0

        # Set sequence number 100
        result = attacker._set_sequence_number(pkt, 100)
        assert (result.SC >> 4) & 0xFFF == 100

        # Set sequence number 4095 (max)
        result = attacker._set_sequence_number(result, 4095)
        assert (result.SC >> 4) & 0xFFF == 4095


# ---------------------------------------------------------------------------
# 9-10. test_packet_handler_*
# ---------------------------------------------------------------------------

class TestPacketHandler:
    def test_packet_handler_captures_response(self, attacker):
        """Mock ICMP reply from target BSSID, verify detection."""
        pkt = MagicMock()

        dot11_layer = MagicMock()
        dot11_layer.addr2 = "aa:bb:cc:dd:ee:ff"
        dot11_layer.addr1 = "11:22:33:44:55:66"

        layers_present = set()
        # Register Dot11 and ICMP as present layers
        mock_dot11_cls = MagicMock()
        mock_icmp_cls = MagicMock()

        # Patch the module-level Dot11 and ICMP references
        with patch("fragattacks.Dot11", mock_dot11_cls), \
             patch("fragattacks.ICMP", mock_icmp_cls):
            layers_present.add(mock_dot11_cls)
            layers_present.add(mock_icmp_cls)

            pkt.haslayer = lambda cls: cls in layers_present
            pkt.__getitem__ = lambda self, cls: dot11_layer if cls is mock_dot11_cls else MagicMock()

            attacker.packet_handler(pkt)

        assert len(attacker.responses) == 1
        assert attacker.responses[0]["src"] == "aa:bb:cc:dd:ee:ff"
        assert attacker.responses[0]["type"] == "icmp_response"

    def test_packet_handler_ignores_unrelated(self, attacker):
        """Wrong BSSID should be ignored."""
        pkt = MagicMock()

        dot11_layer = MagicMock()
        dot11_layer.addr2 = "ff:ff:ff:ff:ff:ff"  # Not our target

        mock_dot11_cls = MagicMock()
        mock_icmp_cls = MagicMock()

        with patch("fragattacks.Dot11", mock_dot11_cls), \
             patch("fragattacks.ICMP", mock_icmp_cls):
            layers_present = {mock_dot11_cls, mock_icmp_cls}
            pkt.haslayer = lambda cls: cls in layers_present
            pkt.__getitem__ = lambda self, cls: dot11_layer if cls is mock_dot11_cls else MagicMock()

            attacker.packet_handler(pkt)

        assert len(attacker.responses) == 0


# ---------------------------------------------------------------------------
# 11. test_save_results_creates_json
# ---------------------------------------------------------------------------

class TestSaveResults:
    def test_save_results_creates_json(self, attacker, tmp_path):
        """Verify output file is created with correct content."""
        attacker.results = {
            "interface": "wlan0mon",
            "target_bssid": "aa:bb:cc:dd:ee:ff",
            "test_mode": "aggregation",
            "tests": [{"test": "amsdu_injection", "vulnerable": False}],
        }
        attacker.output_dir = str(tmp_path / "results")

        filepath = attacker.save_results()
        assert filepath is not None
        assert os.path.isfile(filepath)
        assert filepath.endswith(".json")

        with open(filepath) as f:
            saved = json.load(f)
        assert saved["target_bssid"] == "aa:bb:cc:dd:ee:ff"
        assert len(saved["tests"]) == 1


# ---------------------------------------------------------------------------
# 12. test_get_status
# ---------------------------------------------------------------------------

class TestGetStatus:
    def test_get_status(self, attacker):
        """Verify status fields are present and correct."""
        status = attacker.get_status()

        assert "running" in status
        assert "test_mode" in status
        assert "interface" in status
        assert "target_bssid" in status
        assert "tests_completed" in status
        assert "responses_captured" in status

        assert status["running"] is False
        assert status["test_mode"] == "aggregation"
        assert status["interface"] == "wlan0mon"
        assert status["target_bssid"] == "aa:bb:cc:dd:ee:ff"
        assert status["tests_completed"] == 0
        assert status["responses_captured"] == 0


# ---------------------------------------------------------------------------
# 13. test_cli_mode_choices
# ---------------------------------------------------------------------------

class TestCLI:
    def test_cli_mode_choices(self):
        """Verify that all expected mode choices are defined."""
        expected = {"aggregation", "mixed-key", "cache", "plaintext", "all"}
        assert set(TEST_MODES) == expected

    # -------------------------------------------------------------------
    # 14. test_cli_all_mode_runs_all_tests
    # -------------------------------------------------------------------

    @patch("fragattacks.sniff")
    @patch("fragattacks.sendp")
    def test_cli_all_mode_runs_all_tests(self, mock_sendp, mock_sniff,
                                          mock_interface, tmp_path):
        """Verify 'all' mode runs all four test methods."""
        fa = FragAttacks(
            interface=mock_interface,
            target_bssid="aa:bb:cc:dd:ee:ff",
            target_client="11:22:33:44:55:66",
            timeout=5,
            output_dir=str(tmp_path / "out"),
            test_mode="all",
        )
        results = fa.start()

        # "all" should run all four tests
        assert len(results["tests"]) == 4
        test_names = {t["test"] for t in results["tests"]}
        assert "amsdu_injection" in test_names
        assert "mixed_key_fragment" in test_names
        assert "fragment_cache" in test_names
        assert "plaintext_injection" in test_names
