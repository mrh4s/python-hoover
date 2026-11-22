"""Tests for wifi_direct.py — WiFi Direct (P2P) security testing module."""

import json
import struct
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing the module under test.
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.utils", MagicMock())

import wifi_direct  # noqa: E402
from wifi_direct import (  # noqa: E402
    WiFiDirectTester,
    P2P_OUI,
    P2P_OUI_TYPE,
    P2P_ATTR_GO_INTENT,
    P2P_ATTR_P2P_DEVICE_INFO,
    P2P_ATTR_STATUS,
    GO_NEG_REQUEST,
    CATEGORY_PUBLIC_ACTION,
    PUBLIC_ACTION_VENDOR_SPECIFIC,
    TEST_MODES,
    main,
)

from scapy.layers.dot11 import (  # noqa: E402
    Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeReq, Dot11ProbeResp, Dot11Action,
)


DEVICE_ADDR = "AA:BB:CC:DD:EE:FF"


# ---------------------------------------------------------------------------
# Byte-building helpers
# ---------------------------------------------------------------------------

def _p2p_attr(attr_id: int, body: bytes) -> bytes:
    return bytes([attr_id]) + struct.pack("<H", len(body)) + body


def _device_info_body(device_addr: str = DEVICE_ADDR,
                       config_methods_raw: int = 0x0080,
                       device_name: str = "TestDevice") -> bytes:
    addr_bytes = bytes.fromhex(device_addr.replace(":", ""))
    body = addr_bytes + struct.pack(">H", config_methods_raw)
    body += b"\x00" * 8  # primary device type
    body += b"\x00"      # secondary device type count
    name_bytes = device_name.encode("utf-8")
    body += b"\x10\x11" + struct.pack(">H", len(name_bytes)) + name_bytes
    return body


def _make_p2p_ie_body(device_addr: str = DEVICE_ADDR,
                       config_methods_raw: int = 0x0080,
                       device_name: str = "TestDevice",
                       go_intent: int = None,
                       tie_breaker: int = 0,
                       status: int = None,
                       with_group_info: bool = False) -> bytes:
    """Build raw P2P IE bytes: OUI + OUI type + attributes."""
    attrs = b""
    attrs += _p2p_attr(
        13, _device_info_body(device_addr, config_methods_raw, device_name)
    )
    if go_intent is not None:
        raw_byte = (go_intent << 1) | (tie_breaker & 0x01)
        attrs += _p2p_attr(4, bytes([raw_byte]))
    if status is not None:
        attrs += _p2p_attr(0, bytes([status]))
    if with_group_info:
        attrs += _p2p_attr(14, b"\x00")
        attrs += _p2p_attr(17, bytes([6]))  # operating channel
    return P2P_OUI + bytes([P2P_OUI_TYPE]) + attrs


# ---------------------------------------------------------------------------
# Mock packet helpers
# ---------------------------------------------------------------------------

def _make_elt_chain(elts):
    """Build a chain of mock Dot11Elt-like objects.

    ``elts`` is a list of (tag_id, info_bytes) tuples. Returns the head of
    the chain, wired so that ``elt.payload.getlayer(Dot11Elt)`` returns the
    next element (or None at the end).
    """
    nodes = []
    for tag_id, info in elts:
        node = MagicMock()
        node.ID = tag_id
        node.info = info
        nodes.append(node)

    for i, node in enumerate(nodes):
        nxt = nodes[i + 1] if i + 1 < len(nodes) else None
        node.payload = MagicMock()
        node.payload.getlayer = MagicMock(return_value=nxt)

    return nodes[0] if nodes else None


def _make_packet(layers=None, addr2=None, elt_chain=None, action_payload=None):
    """Build a MagicMock packet simulating scapy Dot11 frames."""
    layers = set(layers or [])
    pkt = MagicMock()
    pkt.haslayer = lambda cls: cls in layers

    dot11_layer = MagicMock()
    dot11_layer.addr2 = addr2

    def getlayer(cls):
        if cls is Dot11Elt:
            return elt_chain
        return None
    pkt.getlayer = getlayer

    def getitem(key):
        if key is Dot11:
            return dot11_layer
        if key is Dot11Action:
            action_mock = MagicMock()
            action_mock.payload = action_payload if action_payload is not None else b""
            return action_mock
        return MagicMock()
    pkt.__getitem__ = MagicMock(side_effect=getitem)

    return pkt


def _make_gon_action_payload(subtype=GO_NEG_REQUEST, extra_attrs: bytes = b""):
    return (
        bytes([CATEGORY_PUBLIC_ACTION, PUBLIC_ACTION_VENDOR_SPECIFIC])
        + P2P_OUI + bytes([P2P_OUI_TYPE, subtype])
        + extra_attrs
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tester(mock_interface, tmp_path):
    return WiFiDirectTester(
        interface=mock_interface,
        output_dir=str(tmp_path / "captures"),
        timeout=5,
    )


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_defaults(self, mock_interface):
        t = WiFiDirectTester(interface=mock_interface)
        assert t.interface == mock_interface
        assert t.test_mode == "discover"
        assert t.target_device is None
        assert t.timeout == 120
        assert t.output_dir == "captures"
        assert t.devices == {}
        assert t.groups == {}
        assert t.gon_frames == []
        assert t.results == {}
        assert t._running is False

    def test_init_custom_params(self, mock_interface):
        t = WiFiDirectTester(
            interface=mock_interface,
            test_mode="analyze",
            target_device=DEVICE_ADDR.lower(),
            timeout=30,
            output_dir="/tmp/p2p_caps",
        )
        assert t.test_mode == "analyze"
        assert t.target_device == DEVICE_ADDR
        assert t.timeout == 30
        assert t.output_dir == "/tmp/p2p_caps"

    def test_all_test_modes_are_valid_choices(self):
        assert "discover" in TEST_MODES
        assert "analyze" in TEST_MODES
        assert "wps-test" in TEST_MODES
        assert "detect-groups" in TEST_MODES
        assert "all" in TEST_MODES


# ---------------------------------------------------------------------------
# _parse_p2p_attributes
# ---------------------------------------------------------------------------

class TestParseP2PAttributes:
    def test_parses_status_attribute(self, tester):
        data = _p2p_attr(P2P_ATTR_STATUS, bytes([1]))
        attrs = tester._parse_p2p_attributes(data)
        assert len(attrs) == 1
        assert attrs[0]["id"] == P2P_ATTR_STATUS
        assert attrs[0]["value"] == 1

    def test_parses_go_intent_attribute(self, tester):
        raw_byte = (7 << 1) | 1
        data = _p2p_attr(P2P_ATTR_GO_INTENT, bytes([raw_byte]))
        attrs = tester._parse_p2p_attributes(data)
        assert attrs[0]["value"]["go_intent"] == 7
        assert attrs[0]["value"]["tie_breaker"] == 1

    def test_handles_truncated_attribute_gracefully(self, tester):
        # Declares a length of 10 bytes but only provides 2.
        data = bytes([P2P_ATTR_STATUS]) + struct.pack("<H", 10) + b"\x01\x02"
        attrs = tester._parse_p2p_attributes(data)
        assert attrs == []

    def test_parses_multiple_attributes_in_sequence(self, tester):
        data = _p2p_attr(P2P_ATTR_STATUS, bytes([0])) + _p2p_attr(
            P2P_ATTR_GO_INTENT, bytes([(3 << 1) | 0])
        )
        attrs = tester._parse_p2p_attributes(data)
        assert len(attrs) == 2
        assert attrs[0]["id"] == P2P_ATTR_STATUS
        assert attrs[1]["id"] == P2P_ATTR_GO_INTENT


# ---------------------------------------------------------------------------
# _parse_p2p_ie
# ---------------------------------------------------------------------------

class TestParseP2PIe:
    def test_parses_device_name_and_config_methods(self, tester):
        body = _make_p2p_ie_body(device_name="MyPhone", config_methods_raw=0x0080)
        parsed = tester._parse_p2p_ie(body)
        assert parsed["device_name"] == "MyPhone"
        assert "PBC" in parsed["config_methods"]

    def test_parses_go_intent_and_tie_breaker(self, tester):
        body = _make_p2p_ie_body(go_intent=10, tie_breaker=1)
        parsed = tester._parse_p2p_ie(body)
        assert parsed["go_intent"] == 10
        assert parsed["tie_breaker"] == 1

    def test_returns_empty_dict_for_non_p2p_ie(self, tester):
        not_p2p = b"\x00\x11\x22\x09" + b"\x00" * 10
        assert tester._parse_p2p_ie(not_p2p) == {}

    def test_returns_empty_dict_for_too_short_ie(self, tester):
        assert tester._parse_p2p_ie(b"\x01\x02") == {}


# ---------------------------------------------------------------------------
# _discover_p2p_devices / packet_handler (device recording)
# ---------------------------------------------------------------------------

class TestDiscoverP2PDevices:
    def test_packet_handler_records_device_from_probe_response(self, tester):
        ie_body = _make_p2p_ie_body(device_name="Printer")
        elt_chain = _make_elt_chain([(221, ie_body)])
        pkt = _make_packet(
            layers={Dot11ProbeResp}, addr2=DEVICE_ADDR.lower(), elt_chain=elt_chain
        )

        tester.packet_handler(pkt)

        assert DEVICE_ADDR in tester.devices
        assert tester.devices[DEVICE_ADDR]["device_name"] == "Printer"

    def test_packet_handler_ignores_non_p2p_probe_response(self, tester):
        elt_chain = _make_elt_chain([(0, b"SomeSSID")])
        pkt = _make_packet(
            layers={Dot11ProbeResp}, addr2=DEVICE_ADDR.lower(), elt_chain=elt_chain
        )

        tester.packet_handler(pkt)

        assert tester.devices == {}

    def test_target_device_filter_excludes_other_devices(self, mock_interface, tmp_path):
        t = WiFiDirectTester(
            interface=mock_interface,
            target_device="11:22:33:44:55:66",
            output_dir=str(tmp_path),
        )
        ie_body = _make_p2p_ie_body(device_name="OtherDevice")
        elt_chain = _make_elt_chain([(221, ie_body)])
        pkt = _make_packet(
            layers={Dot11ProbeResp}, addr2=DEVICE_ADDR.lower(), elt_chain=elt_chain
        )

        t.packet_handler(pkt)

        assert t.devices == {}

    @patch("wifi_direct.sniff")
    def test_discover_p2p_devices_calls_sniff_and_returns_devices(self, mock_sniff, tester):
        ie_body = _make_p2p_ie_body(device_name="Laptop")
        elt_chain = _make_elt_chain([(221, ie_body)])
        pkt = _make_packet(
            layers={Dot11ProbeResp}, addr2=DEVICE_ADDR.lower(), elt_chain=elt_chain
        )

        def fake_sniff(iface, prn, timeout, store, stop_filter):
            prn(pkt)

        mock_sniff.side_effect = fake_sniff

        devices = tester._discover_p2p_devices()

        mock_sniff.assert_called_once()
        assert len(devices) == 1
        assert devices[0]["device_address"] == DEVICE_ADDR


# ---------------------------------------------------------------------------
# _detect_go_negotiation
# ---------------------------------------------------------------------------

class TestDetectGoNegotiation:
    def test_detects_go_negotiation_request(self, tester):
        payload = _make_gon_action_payload(subtype=GO_NEG_REQUEST)
        pkt = _make_packet(layers={Dot11Action}, addr2=DEVICE_ADDR.lower(),
                            action_payload=payload)

        result = tester._detect_go_negotiation(pkt)

        assert result is not None
        assert result["subtype"] == GO_NEG_REQUEST
        assert result["name"] == "GO Negotiation Request"
        assert result["src_mac"] == DEVICE_ADDR.lower()

    def test_returns_none_when_not_action_frame(self, tester):
        pkt = _make_packet(layers=set())
        assert tester._detect_go_negotiation(pkt) is None

    def test_returns_none_for_non_p2p_action_frame(self, tester):
        payload = bytes([CATEGORY_PUBLIC_ACTION, PUBLIC_ACTION_VENDOR_SPECIFIC]) + b"\x00\x11\x22\x01\x00"
        pkt = _make_packet(layers={Dot11Action}, action_payload=payload)
        assert tester._detect_go_negotiation(pkt) is None

    def test_returns_none_for_short_payload(self, tester):
        pkt = _make_packet(layers={Dot11Action}, action_payload=b"\x04\x09")
        assert tester._detect_go_negotiation(pkt) is None

    def test_packet_handler_records_gon_frame(self, tester):
        payload = _make_gon_action_payload(subtype=GO_NEG_REQUEST)
        pkt = _make_packet(layers={Dot11Action}, addr2=DEVICE_ADDR.lower(),
                            action_payload=payload)

        tester.packet_handler(pkt)

        assert len(tester.gon_frames) == 1
        assert tester.gon_frames[0]["name"] == "GO Negotiation Request"


# ---------------------------------------------------------------------------
# _analyze_wps_method
# ---------------------------------------------------------------------------

class TestAnalyzeWpsMethod:
    def test_identifies_pbc_method(self, tester):
        ie_body = _make_p2p_ie_body(config_methods_raw=0x0080)
        elt_chain = _make_elt_chain([(221, ie_body)])
        pkt = _make_packet(layers={Dot11ProbeReq}, elt_chain=elt_chain)
        assert tester._analyze_wps_method(pkt) == "PBC"

    def test_identifies_pin_display_method(self, tester):
        ie_body = _make_p2p_ie_body(config_methods_raw=0x0108)
        elt_chain = _make_elt_chain([(221, ie_body)])
        pkt = _make_packet(layers={Dot11ProbeReq}, elt_chain=elt_chain)
        assert tester._analyze_wps_method(pkt) == "PIN Display"

    def test_returns_none_when_no_p2p_ie_present(self, tester):
        elt_chain = _make_elt_chain([(0, b"SSID")])
        pkt = _make_packet(layers={Dot11ProbeReq}, elt_chain=elt_chain)
        assert tester._analyze_wps_method(pkt) is None


# ---------------------------------------------------------------------------
# _detect_p2p_groups
# ---------------------------------------------------------------------------

class TestDetectP2PGroups:
    @patch("wifi_direct.sniff")
    def test_detects_group_from_beacon_group_info(self, mock_sniff, tester):
        ie_body = _make_p2p_ie_body(with_group_info=True)
        elt_chain = _make_elt_chain([(0, b"DIRECT-ab-MyGroup"), (221, ie_body)])
        pkt = _make_packet(
            layers={Dot11Beacon}, addr2=DEVICE_ADDR.lower(), elt_chain=elt_chain
        )

        def fake_sniff(iface, prn, timeout, store, stop_filter):
            prn(pkt)

        mock_sniff.side_effect = fake_sniff

        groups = tester._detect_p2p_groups()

        assert len(groups) == 1
        assert groups[0]["go_address"] == DEVICE_ADDR
        assert groups[0]["ssid"] == "DIRECT-ab-MyGroup"
        assert groups[0]["channel"] == 6

    @patch("wifi_direct.sniff")
    def test_beacon_without_group_info_is_not_a_group(self, mock_sniff, tester):
        ie_body = _make_p2p_ie_body(with_group_info=False)
        elt_chain = _make_elt_chain([(221, ie_body)])
        pkt = _make_packet(
            layers={Dot11Beacon}, addr2=DEVICE_ADDR.lower(), elt_chain=elt_chain
        )

        def fake_sniff(iface, prn, timeout, store, stop_filter):
            prn(pkt)

        mock_sniff.side_effect = fake_sniff

        groups = tester._detect_p2p_groups()
        assert groups == []


# ---------------------------------------------------------------------------
# _check_go_negotiation_security
# ---------------------------------------------------------------------------

class TestCheckGoNegotiationSecurity:
    def test_flags_maximum_go_intent(self, tester):
        frames = [{
            "src_mac": DEVICE_ADDR,
            "attributes": [
                {"id": P2P_ATTR_GO_INTENT, "value": {"go_intent": 15, "tie_breaker": 0}},
            ],
        }]
        findings = tester._check_go_negotiation_security(frames)
        assert any("GO Intent" in f["issue"] for f in findings)

    def test_flags_pbc_only_wps_method(self, tester):
        frames = [{
            "src_mac": DEVICE_ADDR,
            "attributes": [
                {"id": P2P_ATTR_P2P_DEVICE_INFO,
                 "value": {"config_methods": ["PBC"]}},
            ],
        }]
        findings = tester._check_go_negotiation_security(frames)
        assert any("PBC" in f["issue"] for f in findings)

    def test_flags_failed_negotiation_status(self, tester):
        frames = [{
            "src_mac": DEVICE_ADDR,
            "attributes": [{"id": P2P_ATTR_STATUS, "value": 3}],
        }]
        findings = tester._check_go_negotiation_security(frames)
        assert any("status code 3" in f["issue"] for f in findings)

    def test_no_findings_for_clean_negotiation(self, tester):
        frames = [{
            "src_mac": DEVICE_ADDR,
            "attributes": [
                {"id": P2P_ATTR_GO_INTENT, "value": {"go_intent": 7, "tie_breaker": 0}},
                {"id": P2P_ATTR_STATUS, "value": 0},
                {"id": P2P_ATTR_P2P_DEVICE_INFO,
                 "value": {"config_methods": ["Display", "Keypad"]}},
            ],
        }]
        findings = tester._check_go_negotiation_security(frames)
        assert findings == []

    def test_empty_frame_list_returns_empty_findings(self, tester):
        assert tester._check_go_negotiation_security([]) == []


# ---------------------------------------------------------------------------
# save_results / get_status / stop
# ---------------------------------------------------------------------------

class TestSaveResults:
    def test_save_results_returns_none_when_no_results(self, tester):
        assert tester.save_results() is None

    def test_save_results_writes_json_file(self, tester):
        tester.results = {"mode": "discover", "data": {"devices": []}}
        path = tester.save_results()
        assert path is not None
        with open(path, "r", encoding="utf-8") as f:
            saved = json.load(f)
        assert saved["mode"] == "discover"

    def test_save_results_handles_write_failure(self, tester):
        tester.results = {"mode": "discover"}
        tester.output_dir = "/this/path/does/not/exist/\0bad"
        assert tester.save_results() is None


class TestGetStatus:
    def test_get_status_initial_state(self, tester):
        status = tester.get_status()
        assert status["running"] is False
        assert status["devices_discovered"] == 0
        assert status["groups_detected"] == 0
        assert status["gon_frames_captured"] == 0
        assert status["test_mode"] == "discover"

    def test_get_status_reflects_discovered_devices(self, tester):
        tester.devices[DEVICE_ADDR] = {"device_address": DEVICE_ADDR}
        tester.groups["BB:BB:BB:BB:BB:BB"] = {"go_address": "BB:BB:BB:BB:BB:BB"}
        status = tester.get_status()
        assert status["devices_discovered"] == 1
        assert status["groups_detected"] == 1


class TestStop:
    def test_stop_sets_stop_event_and_clears_running(self, tester):
        tester._running = True
        tester.stop()
        assert tester._stop_event.is_set()
        assert tester._running is False


# ---------------------------------------------------------------------------
# start() orchestration
# ---------------------------------------------------------------------------

class TestStart:
    def test_start_discover_mode(self, tester):
        with patch.object(tester, "_discover_p2p_devices", return_value=[{"device_address": DEVICE_ADDR}]):
            result = tester.start()
        assert result["mode"] == "discover"
        assert result["data"]["devices"] == [{"device_address": DEVICE_ADDR}]
        assert tester._running is False

    def test_start_wps_test_mode_includes_limitation(self, tester):
        tester.test_mode = "wps-test"
        result = tester.start()
        assert "limitation" in result["data"]
        assert "managed-mode" in result["data"]["limitation"]

    def test_start_unknown_mode_logs_error_and_returns(self, tester):
        tester.test_mode = "bogus-mode"
        result = tester.start()
        assert result["data"] == {}


# ---------------------------------------------------------------------------
# CLI parsing (main)
# ---------------------------------------------------------------------------

class TestCli:
    def test_main_invalid_interface_exits(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["wifi_direct.py", "-i", "bad iface!"])
        monkeypatch.setattr(wifi_direct, "require_root", lambda: None)
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1
        assert "Invalid interface" in capsys.readouterr().err

    def test_main_invalid_target_mac_exits(self, monkeypatch, capsys):
        monkeypatch.setattr(
            sys, "argv",
            ["wifi_direct.py", "-i", "wlan0mon", "--target", "not-a-mac"],
        )
        monkeypatch.setattr(wifi_direct, "require_root", lambda: None)
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 1
        assert "Invalid target device MAC" in capsys.readouterr().err

    def test_main_valid_args_runs_and_exits_zero(self, monkeypatch):
        monkeypatch.setattr(
            sys, "argv",
            ["wifi_direct.py", "-i", "wlan0mon", "-m", "discover", "-t", "1"],
        )
        monkeypatch.setattr(wifi_direct, "require_root", lambda: None)
        with patch.object(WiFiDirectTester, "start", return_value={}) as mock_start, \
                patch.object(WiFiDirectTester, "save_results", return_value=None) as mock_save:
            with pytest.raises(SystemExit) as exc:
                main()
        assert exc.value.code == 0
        mock_start.assert_called_once()
        mock_save.assert_called_once()
