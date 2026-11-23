"""Tests for wardriving.py -- GPS/Wardriving module."""

import csv
import json
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
from scapy.layers.dot11 import (  # noqa: E402
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
)

from wardriving import WardrivingMapper, main  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def mapper(mock_interface, tmp_path):
    return WardrivingMapper(
        interface=mock_interface,
        gpsd_host="127.0.0.1",
        gpsd_port=2947,
        output_file=str(tmp_path / "wardriving.json"),
        scan_interval=0.1,
        timeout=5,
        bands="2.4",
    )


def _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", ssid="TestNetwork",
                         channel=6, signal=-65):
    """Create a mock beacon/probe-response packet."""
    pkt = MagicMock()

    dot11_layer = MagicMock()
    dot11_layer.addr3 = bssid

    radiotap_layer = MagicMock()
    radiotap_layer.dBm_AntSignal = signal

    ssid_elt = MagicMock()
    ssid_elt.ID = 0
    ssid_elt.info = ssid.encode("utf-8")

    channel_elt = MagicMock()
    channel_elt.ID = 3
    channel_elt.info = bytes([channel])
    channel_elt.payload.getlayer.return_value = None

    ssid_elt.payload.getlayer.return_value = channel_elt

    layers_present = {Dot11Beacon, Dot11, RadioTap}

    def haslayer(cls):
        return cls in layers_present
    pkt.haslayer = haslayer

    def getlayer(cls):
        if cls is Dot11Elt:
            return ssid_elt
        return None
    pkt.getlayer = getlayer

    def getitem(self, cls):
        if cls is Dot11:
            return dot11_layer
        if cls is RadioTap:
            return radiotap_layer
        return MagicMock()
    pkt.__getitem__ = getitem

    return pkt


# ---------------------------------------------------------------------------
# 1. init defaults
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_defaults(self):
        m = WardrivingMapper(interface="wlan0mon")
        assert m.interface == "wlan0mon"
        assert m.gpsd_host == "127.0.0.1"
        assert m.gpsd_port == 2947
        assert m.output_file == "wardriving.json"
        assert m.scan_interval == 1.0
        assert m.timeout == 0
        assert m.bands == "2.4,5"
        assert m.access_points == {}


# ---------------------------------------------------------------------------
# 2/3. gpsd connection
# ---------------------------------------------------------------------------

class TestGpsdConnection:
    def test_connect_gpsd_success(self, mapper):
        mock_sock = MagicMock()
        with patch("socket.socket", return_value=mock_sock):
            result = mapper._connect_gpsd()
        assert result is True
        assert mapper._gpsd_connected is True
        mock_sock.connect.assert_called_once_with((mapper.gpsd_host, mapper.gpsd_port))
        mock_sock.sendall.assert_called_once()

    def test_connect_gpsd_failure(self, mapper, caplog):
        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_sock.connect.side_effect = OSError("Connection refused")
            mock_socket_cls.return_value = mock_sock
            with caplog.at_level("WARNING"):
                result = mapper._connect_gpsd()
        assert result is False
        assert mapper._gpsd_connected is False
        assert any("gpsd" in rec.message.lower() for rec in caplog.records)


# ---------------------------------------------------------------------------
# 4/5. get_gps_fix
# ---------------------------------------------------------------------------

class TestGetGpsFix:
    def test_get_gps_fix_valid(self, mapper):
        tpv = {
            "class": "TPV", "mode": 3, "lat": 37.7749, "lon": -122.4194,
            "alt": 10.0, "speed": 1.2, "time": "2024-01-01T12:00:00Z",
            "satellites": 8,
        }
        mapper._gpsd_socket = MagicMock()
        mapper._gpsd_socket.recv.return_value = (json.dumps(tpv) + "\n").encode("utf-8")

        fix = mapper._get_gps_fix()

        assert fix is not None
        assert fix["lat"] == 37.7749
        assert fix["lon"] == -122.4194
        assert fix["alt"] == 10.0

    def test_get_gps_fix_no_fix(self, mapper):
        tpv = {"class": "TPV", "mode": 1}
        mapper._gpsd_socket = MagicMock()
        mapper._gpsd_socket.recv.return_value = (json.dumps(tpv) + "\n").encode("utf-8")

        fix = mapper._get_gps_fix()

        assert fix is None


# ---------------------------------------------------------------------------
# 6/7. packet_handler
# ---------------------------------------------------------------------------

class TestPacketHandler:
    def test_packet_handler_associates_gps(self, mapper):
        mapper._current_fix = {"lat": 37.7749, "lon": -122.4194, "alt": 10.0}
        pkt = _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", ssid="TestNetwork")

        mapper.packet_handler(pkt)

        assert "AA:BB:CC:DD:EE:FF" in mapper.access_points
        ap = mapper.access_points["AA:BB:CC:DD:EE:FF"]
        assert len(ap["locations"]) == 1
        assert ap["locations"][0]["lat"] == 37.7749
        assert ap["locations"][0]["lon"] == -122.4194
        assert ap["best_signal_location"] is not None

    def test_packet_handler_no_gps(self, mapper):
        mapper._current_fix = None
        pkt = _make_beacon_packet(bssid="11:22:33:44:55:66", ssid="NoGpsNetwork")

        mapper.packet_handler(pkt)

        assert "11:22:33:44:55:66" in mapper.access_points
        ap = mapper.access_points["11:22:33:44:55:66"]
        assert ap["locations"] == []
        assert ap["best_signal_location"] is None


# ---------------------------------------------------------------------------
# 8. save_results JSON
# ---------------------------------------------------------------------------

class TestSaveResults:
    def test_save_results_json(self, mapper, tmp_path):
        mapper._current_fix = {"lat": 1.0, "lon": 2.0, "alt": 3.0}
        pkt = _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", ssid="SaveTest")
        mapper.packet_handler(pkt)

        path = mapper.save_results()

        assert path == mapper.output_file
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert "AA:BB:CC:DD:EE:FF" in data
        assert data["AA:BB:CC:DD:EE:FF"]["ssid"] == "SaveTest"


# ---------------------------------------------------------------------------
# 9. export_kml
# ---------------------------------------------------------------------------

class TestExportKml:
    def test_export_kml(self, mapper, tmp_path):
        mapper._current_fix = {"lat": 37.7749, "lon": -122.4194, "alt": 10.0}
        pkt = _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", ssid="KmlTest")
        mapper.packet_handler(pkt)

        out_path = str(tmp_path / "out.kml")
        result = mapper.export_kml(out_path)

        assert result == out_path
        with open(out_path, encoding="utf-8") as f:
            content = f.read()
        assert "<kml" in content
        assert "<Placemark>" in content
        assert "KmlTest" in content
        assert "-122.4194,37.7749" in content


# ---------------------------------------------------------------------------
# 10. export_csv Wigle format
# ---------------------------------------------------------------------------

class TestExportCsv:
    def test_export_csv_wigle_format(self, mapper, tmp_path):
        mapper._current_fix = {"lat": 37.7749, "lon": -122.4194, "alt": 10.0}
        pkt = _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", ssid="CsvTest")
        mapper.packet_handler(pkt)

        out_path = str(tmp_path / "out.csv")
        result = mapper.export_csv(out_path)

        assert result == out_path
        with open(out_path, encoding="utf-8") as f:
            lines = f.read().splitlines()

        assert lines[0].startswith("WigleWifi-1.4")
        header = lines[1].split(",")
        assert header == [
            "MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "RSSI",
            "CurrentLatitude", "CurrentLongitude", "AltitudeMeters",
            "AccuracyMeters", "Type",
        ]
        reader = csv.reader(lines[2:])
        row = next(reader)
        assert row[0] == "AA:BB:CC:DD:EE:FF"
        assert row[1] == "CsvTest"


# ---------------------------------------------------------------------------
# 11. get_status with GPS
# ---------------------------------------------------------------------------

class TestGetStatus:
    def test_get_status_with_gps(self, mapper):
        mapper._gpsd_connected = True
        mapper._current_fix = {"lat": 1.0, "lon": 2.0, "alt": 3.0}
        pkt = _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF")
        mapper.packet_handler(pkt)

        status = mapper.get_status()

        assert status["gpsd_connected"] is True
        assert status["current_fix"]["lat"] == 1.0
        assert status["ap_count"] == 1


# ---------------------------------------------------------------------------
# 12. multiple sightings
# ---------------------------------------------------------------------------

class TestMultipleSightings:
    def test_multiple_sightings(self, mapper):
        mapper._current_fix = {"lat": 1.0, "lon": 1.0, "alt": 0.0}
        pkt1 = _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", signal=-70)
        mapper.packet_handler(pkt1)

        mapper._current_fix = {"lat": 2.0, "lon": 2.0, "alt": 0.0}
        pkt2 = _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", signal=-60)
        mapper.packet_handler(pkt2)

        ap = mapper.access_points["AA:BB:CC:DD:EE:FF"]
        assert len(ap["locations"]) == 2
        assert ap["locations"][0]["lat"] == 1.0
        assert ap["locations"][1]["lat"] == 2.0


# ---------------------------------------------------------------------------
# 13. best signal location
# ---------------------------------------------------------------------------

class TestBestSignalLocation:
    def test_best_signal_location(self, mapper):
        mapper._current_fix = {"lat": 1.0, "lon": 1.0, "alt": 0.0}
        pkt_weak = _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", signal=-80)
        mapper.packet_handler(pkt_weak)

        mapper._current_fix = {"lat": 2.0, "lon": 2.0, "alt": 0.0}
        pkt_strong = _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", signal=-50)
        mapper.packet_handler(pkt_strong)

        mapper._current_fix = {"lat": 3.0, "lon": 3.0, "alt": 0.0}
        pkt_mid = _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", signal=-65)
        mapper.packet_handler(pkt_mid)

        ap = mapper.access_points["AA:BB:CC:DD:EE:FF"]
        assert ap["best_signal_location"]["signal"] == -50
        assert ap["best_signal_location"]["lat"] == 2.0


# ---------------------------------------------------------------------------
# 14. CLI format choices
# ---------------------------------------------------------------------------

class TestCliFormatChoices:
    def test_cli_format_choices(self, mock_interface, tmp_path, monkeypatch):
        output = str(tmp_path / "out.json")
        monkeypatch.setattr(
            sys, "argv",
            ["wardriving.py", "-i", mock_interface, "-o", output, "-f", "bogus"],
        )
        with patch("wardriving.require_root"):
            with pytest.raises(SystemExit):
                main()

    def test_cli_format_choices_valid(self, mock_interface, tmp_path, monkeypatch):
        output = str(tmp_path / "out.json")
        monkeypatch.setattr(
            sys, "argv",
            ["wardriving.py", "-i", mock_interface, "-o", output, "-f", "all", "-t", "1"],
        )
        with patch("wardriving.require_root"), \
             patch.object(WardrivingMapper, "start") as mock_start, \
             patch.object(WardrivingMapper, "export_kml") as mock_kml, \
             patch.object(WardrivingMapper, "export_csv") as mock_csv:
            main()
        mock_start.assert_called_once()
        mock_kml.assert_called_once()
        mock_csv.assert_called_once()
