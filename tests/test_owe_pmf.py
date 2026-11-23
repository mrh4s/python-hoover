"""Tests for OWE detection and PMF analysis in ap_scanner.py."""

import sys
from unittest.mock import MagicMock

import pytest

sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

from scapy.layers.dot11 import Dot11, Dot11Beacon, RadioTap  # noqa: E402

from ap_scanner import APScanner  # noqa: E402

BSSID = "AA:BB:CC:DD:EE:FF"


@pytest.fixture
def scanner(mock_interface):
    return APScanner(interface=mock_interface, timeout=10)


def _make_rsn(*akm_types, caps=None, pairwise=(4,), group=4):
    rsn = b"\x01\x00" + b"\x00\x0f\xac" + bytes([group])
    rsn += len(pairwise).to_bytes(2, "little")
    for p in pairwise:
        rsn += b"\x00\x0f\xac" + bytes([p])
    rsn += len(akm_types).to_bytes(2, "little")
    for a in akm_types:
        rsn += b"\x00\x0f\xac" + bytes([a])
    if caps is not None:
        rsn += caps.to_bytes(2, "little")
    return rsn


def _owe_ie(bssid="11:22:33:44:55:66", ssid="OpenNet"):
    return (
        b"\x50\x6f\x9a\x1c"
        + bytes.fromhex(bssid.replace(":", ""))
        + bytes([len(ssid)])
        + ssid.encode()
    )


def _make_packet(elts, has_privacy=True, ssid="TestNet", channel=6):
    """Build a mock beacon. elts: list of (ID, info) appended after SSID/DS."""
    pkt = MagicMock()
    layers = {Dot11Beacon, RadioTap, Dot11}
    pkt.haslayer = lambda cls: cls in layers
    dot11 = MagicMock()
    dot11.addr3 = BSSID
    beacon = MagicMock()
    beacon.cap = 0x0011 if has_privacy else 0x0001
    radiotap = MagicMock()
    radiotap.dBm_AntSignal = -50
    table = {Dot11: dot11, Dot11Beacon: beacon, RadioTap: radiotap}
    pkt.__getitem__ = lambda self, cls: table.get(cls, dot11)

    chain = [(0, ssid.encode()), (3, bytes([channel]))] + list(elts)
    nodes = []
    for eid, info in chain:
        n = MagicMock()
        n.ID = eid
        n.info = info
        nodes.append(n)
    for i, n in enumerate(nodes):
        nxt = nodes[i + 1] if i + 1 < len(nodes) else None
        n.payload = MagicMock()
        n.payload.getlayer = MagicMock(return_value=nxt)
    pkt.getlayer = MagicMock(return_value=nodes[0])
    return pkt


class TestRSNCapabilities:
    def test_parse_rsn_capabilities_pmf_capable(self, scanner):
        r = scanner._parse_rsn_capabilities((0x0080).to_bytes(2, "little"))
        assert r["pmf_capable"] is True
        assert r["pmf_required"] is False

    def test_parse_rsn_capabilities_pmf_required(self, scanner):
        r = scanner._parse_rsn_capabilities((0x0040).to_bytes(2, "little"))
        assert r["pmf_required"] is True
        assert r["pmf_capable"] is False

    def test_parse_rsn_capabilities_no_pmf(self, scanner):
        r = scanner._parse_rsn_capabilities(b"\x00\x00")
        assert r["pmf_capable"] is False
        assert r["pmf_required"] is False
        assert r["rsn_capabilities"] == 0

    def test_parse_rsn_capabilities_both_set(self, scanner):
        r = scanner._parse_rsn_capabilities((0x00C0).to_bytes(2, "little"))
        assert r["pmf_capable"] is True
        assert r["pmf_required"] is True

    def test_parse_rsn_ie_extended(self, scanner):
        caps = 0x00C0 | 0x0001 | (2 << 2) | (3 << 4)
        r = scanner._parse_rsn_ie(_make_rsn(8, caps=caps))
        assert r["akm_suites"] == ["SAE"]
        assert r["pairwise_ciphers"] == ["CCMP"]
        assert r["group_cipher"] == "CCMP"
        assert r["rsn_capabilities"] == caps
        assert r["pmf_capable"] is True
        assert r["pmf_required"] is True
        assert r["pre_auth"] is True
        assert r["no_pairwise"] is False
        assert r["ptksa_replay_counters"] == 2
        assert r["gtksa_replay_counters"] == 3


class TestOWE:
    def test_detect_owe_by_akm(self, scanner):
        pkt = _make_packet([(48, _make_rsn(18, caps=0x00C0))])
        assert scanner._detect_owe_network(pkt) is True
        assert scanner._detect_owe_network(_make_packet([(48, _make_rsn(2))])) is False

    def test_detect_owe_transition_ie(self, scanner):
        r = scanner._parse_owe_transition_ie(_owe_ie(ssid="OpenNet"))
        assert r is not None
        assert r["ssid"] == "OpenNet"
        assert scanner._parse_owe_transition_ie(b"\x00\x50\xf2\x01abc") is None
        pkt = _make_packet([(221, _owe_ie())], has_privacy=False)
        assert scanner._detect_owe_network(pkt) is True

    def test_owe_transition_bssid_extraction(self, scanner):
        r = scanner._parse_owe_transition_ie(_owe_ie(bssid="de:ad:be:ef:00:01"))
        assert r["bssid"] == "DE:AD:BE:EF:00:01"

    def test_encryption_from_akms_owe(self, scanner):
        assert scanner._encryption_from_akms(["OWE"]) == "OWE"


class TestPacketHandlerFields:
    def test_packet_handler_stores_pmf_fields(self, scanner):
        scanner.packet_handler(_make_packet([(48, _make_rsn(8, caps=0x00C0))]))
        ap = scanner.access_points[BSSID]
        assert ap["pmf_capable"] is True
        assert ap["pmf_required"] is True
        assert ap["owe_mode"] is None

    def test_packet_handler_stores_owe_fields(self, scanner):
        pkt = _make_packet([(48, _make_rsn(18, caps=0x00C0)), (221, _owe_ie())])
        scanner.packet_handler(pkt)
        ap = scanner.access_points[BSSID]
        assert ap["owe_mode"] == "owe_transition"
        assert ap["owe_transition_bssid"] == "11:22:33:44:55:66"
        assert ap["owe_transition_ssid"] == "OpenNet"
        assert ap["encryption"] == "OWE-Transition"

        s2 = APScanner(interface="wlan0mon")
        s2.packet_handler(_make_packet([(48, _make_rsn(18))]))
        assert s2.access_points[BSSID]["owe_mode"] == "owe"
        assert s2.access_points[BSSID]["encryption"] == "OWE"


class TestPrintPMF:
    def test_print_results_shows_pmf(self, scanner, capsys):
        scanner.access_points = {
            BSSID: {
                "ssid": "TestNet",
                "channel": 6,
                "signal": -50,
                "encryption": "WPA3",
                "vendor": "V",
                "beacon_count": 1,
                "pmf_capable": True,
                "pmf_required": True,
                "owe_mode": None,
            },
        }
        scanner.print_results()
        out = capsys.readouterr().out
        assert "PMF" in out
        assert "Required" in out
