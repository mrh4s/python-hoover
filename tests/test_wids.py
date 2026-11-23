"""Tests for wids.py — Wireless Intrusion Detection System."""

import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.layers.eap", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

# Import mocked classes
from scapy.layers.dot11 import (  # noqa: E402
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
)
from scapy.layers.eap import EAPOL  # noqa: E402

from wids import Alert, WIDSMonitor  # noqa: E402


@pytest.fixture
def monitor(mock_interface, tmp_path):
    return WIDSMonitor(
        interface=mock_interface,
        log_file=str(tmp_path / "alerts.json"),
        channel_hop=False,
    )


def _make_beacon_packet(bssid="AA:BB:CC:DD:EE:FF", ssid="TestNet"):
    pkt = MagicMock()
    layers_present = {Dot11Beacon, Dot11}
    pkt.haslayer = lambda cls: cls in layers_present

    dot11 = MagicMock()
    dot11.addr2 = bssid
    dot11.addr3 = bssid
    pkt.__getitem__ = lambda self, cls: dot11

    ssid_elt = MagicMock()
    ssid_elt.ID = 0
    ssid_elt.info = ssid.encode()
    end_elt = MagicMock()
    end_elt.ID = 255
    end_elt.payload = MagicMock()
    end_elt.payload.getlayer = MagicMock(return_value=None)
    ssid_elt.payload = MagicMock()
    ssid_elt.payload.getlayer = MagicMock(return_value=end_elt)
    pkt.getlayer = MagicMock(return_value=ssid_elt)
    return pkt


def _make_deauth_packet(addr2="AA:BB:CC:DD:EE:FF", addr1="11:22:33:44:55:66"):
    pkt = MagicMock()
    layers_present = {Dot11Deauth, Dot11}
    pkt.haslayer = lambda cls: cls in layers_present

    dot11 = MagicMock()
    dot11.addr1 = addr1
    dot11.addr2 = addr2
    dot11.addr3 = addr2
    pkt.__getitem__ = lambda self, cls: dot11
    return pkt


def _make_eapol_packet(addr2="AA:BB:CC:DD:EE:FF", addr3="AA:BB:CC:DD:EE:FF"):
    pkt = MagicMock()
    layers_present = {EAPOL, Dot11}
    pkt.haslayer = lambda cls: cls in layers_present

    dot11 = MagicMock()
    dot11.addr2 = addr2
    dot11.addr3 = addr3
    pkt.__getitem__ = lambda self, cls: dot11
    return pkt


class TestWIDSMonitorInit:
    def test_defaults(self, mock_interface):
        m = WIDSMonitor(interface=mock_interface)
        assert m.interface == mock_interface
        assert m.known_aps == {}
        assert m.alerts == []
        assert m.deauth_threshold == 10
        assert m.deauth_window == 5

    def test_custom_thresholds(self, mock_interface):
        m = WIDSMonitor(interface=mock_interface, deauth_threshold=5, deauth_window=3)
        assert m.deauth_threshold == 5
        assert m.deauth_window == 3


class TestKnownAPs:
    def test_load_known_aps(self, monitor, tmp_path):
        aps_file = tmp_path / "known_aps.json"
        aps_file.write_text(json.dumps({
            "AA:BB:CC:DD:EE:FF": {"ssid": "HomeNet", "channel": 6},
        }))
        monitor.load_known_aps(str(aps_file))
        assert "AA:BB:CC:DD:EE:FF" in monitor.known_aps

    def test_load_missing_file(self, monitor):
        monitor.load_known_aps("/nonexistent/file.json")
        assert monitor.known_aps == {}

    def test_add_known_ap(self, monitor):
        monitor.add_known_ap("AA:BB:CC:DD:EE:FF", "HomeNet", 6)
        assert "AA:BB:CC:DD:EE:FF" in monitor.known_aps
        assert monitor.known_aps["AA:BB:CC:DD:EE:FF"]["ssid"] == "HomeNet"


class TestRogueAPDetection:
    @patch("wids.lookup_vendor", return_value="TestVendor")
    def test_new_unknown_ap_alert(self, mock_vendor, monitor):
        pkt = _make_beacon_packet()
        monitor.packet_handler(pkt)
        assert len(monitor.alerts) == 1
        assert monitor.alerts[0].alert_type == "ROGUE_AP"
        assert monitor.alerts[0].severity == "MEDIUM"

    @patch("wids.lookup_vendor", return_value="TestVendor")
    def test_known_ap_no_rogue_alert(self, mock_vendor, monitor):
        monitor.add_known_ap("AA:BB:CC:DD:EE:FF", "TestNet")
        pkt = _make_beacon_packet()
        monitor.packet_handler(pkt)
        rogue_alerts = [a for a in monitor.alerts if a.alert_type == "ROGUE_AP"]
        assert len(rogue_alerts) == 0


class TestEvilTwinDetection:
    @patch("wids.lookup_vendor", return_value="TestVendor")
    def test_evil_twin_detected(self, mock_vendor, monitor):
        monitor.add_known_ap("AA:BB:CC:DD:EE:FF", "CorpNet")
        pkt = _make_beacon_packet(bssid="11:22:33:44:55:66", ssid="CorpNet")
        monitor.packet_handler(pkt)
        twin_alerts = [a for a in monitor.alerts if a.alert_type == "EVIL_TWIN"]
        assert len(twin_alerts) == 1
        assert twin_alerts[0].severity == "HIGH"


class TestKarmaDetection:
    @patch("wids.lookup_vendor", return_value="TestVendor")
    def test_karma_attack_detected(self, mock_vendor, monitor):
        bssid = "AA:BB:CC:DD:EE:FF"
        for i in range(5):
            pkt = _make_beacon_packet(bssid=bssid, ssid=f"Network{i}")
            monitor.packet_handler(pkt)
        karma_alerts = [a for a in monitor.alerts if a.alert_type == "KARMA_ATTACK"]
        assert len(karma_alerts) >= 1


class TestDeauthFloodDetection:
    def test_flood_detected(self, monitor):
        monitor.deauth_threshold = 5
        monitor.deauth_window = 10
        for _ in range(6):
            pkt = _make_deauth_packet()
            monitor.packet_handler(pkt)
        flood_alerts = [a for a in monitor.alerts if a.alert_type == "DEAUTH_FLOOD"]
        assert len(flood_alerts) >= 1
        assert flood_alerts[0].severity == "CRITICAL"

    def test_below_threshold_no_alert(self, monitor):
        monitor.deauth_threshold = 10
        for _ in range(3):
            pkt = _make_deauth_packet()
            monitor.packet_handler(pkt)
        flood_alerts = [a for a in monitor.alerts if a.alert_type == "DEAUTH_FLOOD"]
        assert len(flood_alerts) == 0

    def test_tracker_cleanup(self, monitor):
        monitor.deauth_window = 1
        monitor.deauth_threshold = 100
        pkt = _make_deauth_packet()
        monitor.packet_handler(pkt)
        assert len(monitor._deauth_tracker.get("AA:BB:CC:DD:EE:FF", [])) == 1

        monitor._deauth_tracker["AA:BB:CC:DD:EE:FF"] = [time.time() - 10]
        monitor.packet_handler(pkt)
        assert len(monitor._deauth_tracker.get("AA:BB:CC:DD:EE:FF", [])) == 1


class TestEAPOLAnomaly:
    def test_high_eapol_volume(self, monitor):
        for _ in range(25):
            pkt = _make_eapol_packet()
            monitor.packet_handler(pkt)
        eapol_alerts = [a for a in monitor.alerts if a.alert_type == "EAPOL_ANOMALY"]
        assert len(eapol_alerts) >= 1


class TestRaiseAlert:
    def test_callback_invoked(self, monitor):
        callback = MagicMock()
        monitor.alert_callback = callback
        monitor._raise_alert("HIGH", "TEST", "Test alert", "AA:BB:CC:DD:EE:FF", {})
        callback.assert_called_once()
        alert = callback.call_args[0][0]
        assert isinstance(alert, Alert)

    def test_alert_appended(self, monitor):
        monitor._raise_alert("LOW", "TEST", "Test", "AA:BB:CC:DD:EE:FF", {})
        assert len(monitor.alerts) == 1
        assert monitor.alerts[0].severity == "LOW"


class TestGetStats:
    def test_stats_dict(self, monitor):
        monitor._start_time = time.time()
        stats = monitor.get_stats()
        assert "packets_processed" in stats
        assert "alerts_total" in stats
        assert "unique_aps_seen" in stats
        assert "uptime_seconds" in stats


class TestGetAlerts:
    def test_filter_by_severity(self, monitor):
        monitor._raise_alert("HIGH", "A", "d", "M", {})
        monitor._raise_alert("LOW", "B", "d", "M", {})
        result = monitor.get_alerts(severity="HIGH")
        assert len(result) == 1
        assert result[0].severity == "HIGH"

    def test_filter_by_type(self, monitor):
        monitor._raise_alert("HIGH", "DEAUTH_FLOOD", "d", "M", {})
        monitor._raise_alert("HIGH", "EVIL_TWIN", "d", "M", {})
        result = monitor.get_alerts(alert_type="EVIL_TWIN")
        assert len(result) == 1

    def test_limit(self, monitor):
        for i in range(10):
            monitor._raise_alert("LOW", "TEST", f"Alert {i}", "M", {})
        result = monitor.get_alerts(limit=3)
        assert len(result) == 3


class TestSaveAlerts:
    def test_save_json(self, monitor):
        monitor._raise_alert("HIGH", "TEST", "Test alert", "AA:BB:CC:DD:EE:FF", {"key": "val"})
        monitor.save_alerts()
        assert os.path.exists(monitor.log_file)
        with open(monitor.log_file) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["severity"] == "HIGH"

    def test_save_empty(self, monitor):
        monitor.save_alerts()


class TestAlertDataclass:
    def test_fields(self):
        a = Alert(
            timestamp="2024-01-01", severity="HIGH",
            alert_type="TEST", description="desc",
            source_mac="AA:BB:CC:DD:EE:FF", details={"k": "v"},
        )
        assert a.timestamp == "2024-01-01"
        assert a.severity == "HIGH"
        assert a.details == {"k": "v"}


class TestChannelHop:
    @patch("wids.subprocess.run")
    @patch("wids.time.sleep", side_effect=StopIteration)
    def test_hop_loop(self, mock_sleep, mock_run, monitor):
        monitor._hop_running = True
        with pytest.raises(StopIteration):
            monitor._channel_hop_loop()
        mock_run.assert_called_once()

    def test_default_bands(self, monitor):
        assert monitor.bands == "2.4"

    @patch("wids.subprocess.run")
    @patch("wids.time.sleep", side_effect=StopIteration)
    def test_hop_loop_6ghz_band(self, mock_sleep, mock_run, mock_interface, tmp_path):
        m = WIDSMonitor(
            interface=mock_interface,
            log_file=str(tmp_path / "alerts.json"),
            channel_hop=False,
            bands="6",
        )
        m._hop_running = True
        with pytest.raises(StopIteration):
            m._channel_hop_loop()
        args = mock_run.call_args[0][0]
        assert "1" in args


class TestPrintSummary:
    def test_print(self, monitor, capsys):
        monitor._start_time = time.time()
        monitor._stats["packets_processed"] = 100
        monitor._raise_alert("HIGH", "TEST", "Test", "M", {})
        monitor.print_summary()
        captured = capsys.readouterr()
        assert "WIDS Summary" in captured.out
        assert "100" in captured.out
