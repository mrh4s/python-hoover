"""Tests for hoover.py's client fingerprinting features (scapy mocked)."""

import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock scapy before importing hoover, since scapy may not be installed.
# ---------------------------------------------------------------------------
_scapy_dot11_mock = MagicMock()
_scapy_sendrecv_mock = MagicMock()

sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", _scapy_dot11_mock)
sys.modules.setdefault("scapy.layers.eap", MagicMock())
sys.modules.setdefault("scapy.sendrecv", _scapy_sendrecv_mock)
sys.modules.setdefault("scapy.utils", MagicMock())
sys.modules.setdefault("scapy.packet", MagicMock())

import hoover as _hoover_module  # noqa: E402
from hoover import ClientFingerprint, ProbeMonitor  # noqa: E402

# Grab the actual mock objects hoover.py imported, so our fake packets
# dispatch on the same identity the production code uses.
_Dot11 = _hoover_module.Dot11
_Dot11Elt = _hoover_module.Dot11Elt
_Dot11ProbeReq = _hoover_module.Dot11ProbeReq


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_elt(eid, info):
    """Build a fake Dot11Elt-like mock with the given IE id and info bytes."""
    elt = MagicMock()
    elt.ID = eid
    elt.info = info
    return elt


def _chain_elts(elts):
    """Chain a list of fake IE mocks via .payload.getlayer(Dot11Elt)."""
    for i, elt in enumerate(elts):
        next_elt = elts[i + 1] if i + 1 < len(elts) else None
        elt.payload = MagicMock()
        elt.payload.getlayer = MagicMock(
            side_effect=lambda layer, _ne=next_elt: _ne if layer is _Dot11Elt else None
        )
    return elts[0] if elts else None


def _make_probe_packet(client_mac="AA:BB:CC:DD:EE:FF", ies=None, signal_dbm=-50):
    """Build a fake scapy packet that looks like a Dot11ProbeReq with IEs."""
    pkt = MagicMock()
    pkt.haslayer.return_value = True

    dot11_layer = MagicMock()
    dot11_layer.addr2 = client_mac

    def getitem(key):
        if key is _Dot11:
            return dot11_layer
        return MagicMock()

    pkt.__getitem__ = MagicMock(side_effect=getitem)
    pkt.dBm_AntSignal = signal_dbm

    ies = ies or []
    elts = [_make_elt(eid, info) for eid, info in ies]
    first = _chain_elts(elts)

    def getlayer(layer):
        if layer is _Dot11Elt:
            return first
        return None

    pkt.getlayer = MagicMock(side_effect=getlayer)
    return pkt


def _make_wps_tlv(attr_type, value_bytes):
    return attr_type.to_bytes(2, "big") + len(value_bytes).to_bytes(2, "big") + value_bytes


def _make_wps_ie(device_name=None, manufacturer=None, model_name=None, model_number=None):
    body = b"\x00\x50\xf2\x04"
    if device_name is not None:
        body += _make_wps_tlv(0x1011, device_name.encode("utf-8"))
    if manufacturer is not None:
        body += _make_wps_tlv(0x1021, manufacturer.encode("utf-8"))
    if model_name is not None:
        body += _make_wps_tlv(0x1023, model_name.encode("utf-8"))
    if model_number is not None:
        body += _make_wps_tlv(0x1024, model_number.encode("utf-8"))
    return body


# ---------------------------------------------------------------------------
# Rate parsing
# ---------------------------------------------------------------------------

class TestRateParsing:
    """Tests for _parse_supported_rates and _parse_extended_rates."""

    def test_parse_supported_rates(self):
        pm = ProbeMonitor(interface="wlan0mon")
        rates = pm._parse_supported_rates(b"\x82\x84\x8b\x96")
        assert rates == [1.0, 2.0, 5.5, 11.0]

    def test_parse_supported_rates_non_basic(self):
        pm = ProbeMonitor(interface="wlan0mon")
        rates = pm._parse_supported_rates(b"\x0c\x12\x18\x24")
        assert rates == [6.0, 9.0, 12.0, 18.0]

    def test_parse_extended_rates(self):
        pm = ProbeMonitor(interface="wlan0mon")
        rates = pm._parse_extended_rates(b"\x30\x60\x6c")
        assert rates == [24.0, 48.0, 54.0]


# ---------------------------------------------------------------------------
# HT / VHT capabilities
# ---------------------------------------------------------------------------

class TestHTVHTCapabilities:
    """Tests for _parse_ht_capabilities and _parse_vht_capabilities."""

    def test_parse_ht_capabilities_40mhz(self):
        pm = ProbeMonitor(interface="wlan0mon")
        # Bit 1 set (0x0002) -> 40 MHz channel width supported.
        info = bytes([0x02, 0x00]) + bytes(24)
        result = pm._parse_ht_capabilities(info)
        assert result["channel_width_40"] is True

    def test_parse_ht_capabilities_20mhz_only(self):
        pm = ProbeMonitor(interface="wlan0mon")
        # Bit 1 clear -> 20 MHz only.
        info = bytes([0x00, 0x00]) + bytes(24)
        result = pm._parse_ht_capabilities(info)
        assert result["channel_width_40"] is False

    def test_parse_vht_capabilities(self):
        pm = ProbeMonitor(interface="wlan0mon")
        info = bytes([0x00, 0x00, 0x00, 0x00]) + bytes(8)
        result = pm._parse_vht_capabilities(info)
        assert result["vht_capable"] is True


# ---------------------------------------------------------------------------
# WPS IE parsing
# ---------------------------------------------------------------------------

class TestWPSParsing:
    """Tests for _parse_wps_ie."""

    def test_parse_wps_ie_device_name(self):
        pm = ProbeMonitor(interface="wlan0mon")
        info = _make_wps_ie(device_name="MyPhone")
        result = pm._parse_wps_ie(info)
        assert result["wps_enabled"] is True
        assert result["device_name"] == "MyPhone"


# ---------------------------------------------------------------------------
# Power capability parsing
# ---------------------------------------------------------------------------

class TestPowerCapability:
    """Tests for _parse_power_capability."""

    def test_parse_power_capability(self):
        pm = ProbeMonitor(interface="wlan0mon")
        result = pm._parse_power_capability(b"\xf0\x14")
        assert result == (-16, 20)


# ---------------------------------------------------------------------------
# OS / device type guessing
# ---------------------------------------------------------------------------

class TestOSGuessing:
    """Tests for _guess_os."""

    def test_guess_os_apple(self):
        pm = ProbeMonitor(interface="wlan0mon")
        fp = ClientFingerprint()
        fp.vendor = "Apple"
        fp.ht_capable = True
        fp.supported_rates = [1.0, 2.0, 5.5, 11.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0]
        assert pm._guess_os(fp) == "iOS/macOS"

    def test_guess_os_unknown(self):
        pm = ProbeMonitor(interface="wlan0mon")
        fp = ClientFingerprint()
        fp.vendor = "Unknown"
        fp.supported_rates = [1.0, 2.0]
        assert pm._guess_os(fp) == "Unknown"


class TestDeviceTypeGuessing:
    """Tests for _guess_device_type."""

    def test_guess_device_type_phone(self):
        pm = ProbeMonitor(interface="wlan0mon")
        fp = ClientFingerprint()
        fp.vendor = "Samsung"
        fp.ht_capable = True
        fp.vht_capable = True
        fp.he_capable = False
        assert pm._guess_device_type(fp) == "Phone"


# ---------------------------------------------------------------------------
# fingerprint_client (full extraction)
# ---------------------------------------------------------------------------

class TestFingerprintClient:
    """Tests for fingerprint_client."""

    def test_fingerprint_client_full(self):
        pm = ProbeMonitor(interface="wlan0mon")
        ies = [
            (0, b"HomeWifi"),
            (1, b"\x82\x84\x8b\x96"),
            (50, b"\x0c\x12\x18\x24"),
            (33, b"\xf0\x14"),
            (45, bytes([0x02, 0x00]) + bytes(24)),
            (191, bytes([0x00, 0x00, 0x00, 0x00]) + bytes(8)),
            (221, _make_wps_ie(device_name="Pixel-7")),
        ]
        pkt = _make_probe_packet(client_mac="10:52:1C:AA:BB:CC", ies=ies)

        fp = pm.fingerprint_client(pkt)

        assert fp is not None
        assert fp.mac == "10:52:1C:AA:BB:CC"
        assert "HomeWifi" in fp.probed_ssids
        assert fp.supported_rates == [1.0, 2.0, 5.5, 11.0]
        assert fp.extended_rates == [6.0, 9.0, 12.0, 18.0]
        assert fp.power_capability == (-16, 20)
        assert fp.ht_capable is True
        assert fp.ht_channel_width_40 is True
        assert fp.vht_capable is True
        assert fp.wps_enabled is True
        assert fp.wps_device_name == "Pixel-7"
        assert fp.probe_count == 1
        assert "10:52:1C:AA:BB:CC" in pm.fingerprints

    def test_fingerprint_client_minimal(self):
        pm = ProbeMonitor(interface="wlan0mon")
        ies = [
            (0, b"MinimalNet"),
            (1, b"\x82\x84\x8b\x96"),
        ]
        pkt = _make_probe_packet(client_mac="AA:BB:CC:DD:EE:FF", ies=ies)

        fp = pm.fingerprint_client(pkt)

        assert fp is not None
        assert "MinimalNet" in fp.probed_ssids
        assert fp.supported_rates == [1.0, 2.0, 5.5, 11.0]
        assert fp.ht_capable is False
        assert fp.vht_capable is False
        assert fp.he_capable is False
        assert fp.wps_enabled is False


# ---------------------------------------------------------------------------
# get_fingerprints
# ---------------------------------------------------------------------------

class TestGetFingerprints:
    """Tests for get_fingerprints."""

    def test_get_fingerprints_returns_dict(self):
        pm = ProbeMonitor(interface="wlan0mon")
        ies = [(0, b"SomeSSID"), (1, b"\x82\x84")]
        pkt = _make_probe_packet(client_mac="AA:BB:CC:DD:EE:FF", ies=ies)
        pm.fingerprint_client(pkt)

        result = pm.get_fingerprints()

        assert isinstance(result, dict)
        assert "AA:BB:CC:DD:EE:FF" in result
        entry = result["AA:BB:CC:DD:EE:FF"]
        assert isinstance(entry, dict)
        assert isinstance(entry["probed_ssids"], list)
        assert "SomeSSID" in entry["probed_ssids"]
        import json
        json.dumps(result)  # must be JSON-serializable


# ---------------------------------------------------------------------------
# CLI flag
# ---------------------------------------------------------------------------

class TestCLIFingerprintFlag:
    """Tests for the --fingerprint CLI flag."""

    @patch("hoover.ProbeMonitor")
    @patch("hoover.OutputWriter")
    @patch("hoover.check_monitor_mode", return_value=True)
    @patch("hoover.require_root")
    def test_cli_fingerprint_flag(self, mock_require_root, mock_check_mm,
                                   mock_output_writer, mock_probe_monitor):
        test_args = ["hoover.py", "-i", "wlan0mon", "--fingerprint"]
        with patch.object(sys, "argv", test_args):
            _hoover_module.main()

        assert mock_probe_monitor.called
        _, kwargs = mock_probe_monitor.call_args
        assert kwargs["fingerprint_mode"] is True
