"""Tests for hoover.py — ProbeMonitor and OutputWriter (scapy mocked)."""

import csv
import json
import sqlite3
import sys
from collections import defaultdict
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock scapy before importing hoover, since scapy may not be installed.
# ---------------------------------------------------------------------------
_scapy_dot11_mock = MagicMock()
_scapy_sendrecv_mock = MagicMock()

sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", _scapy_dot11_mock)
sys.modules.setdefault("scapy.sendrecv", _scapy_sendrecv_mock)

import hoover as _hoover_module  # noqa: E402
from hoover import OutputWriter, ProbeMonitor, _color  # noqa: E402

# Grab the actual mock objects that hoover.py imported, so our packet mock
# dispatches on the same identity the production code uses.
_Dot11 = _hoover_module.Dot11
_Dot11Elt = _hoover_module.Dot11Elt
_Dot11ProbeReq = _hoover_module.Dot11ProbeReq


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_probe_packet(client_mac="AA:BB:CC:DD:EE:FF", ssid="TestSSID",
                       signal_dbm=-50):
    """Build a fake scapy packet that looks like a Dot11ProbeReq."""
    pkt = MagicMock()
    pkt.haslayer.return_value = True

    # pkt[Dot11].addr2
    dot11_layer = MagicMock()
    dot11_layer.addr2 = client_mac

    dot11elt_layer = MagicMock()
    dot11elt_layer.info = ssid.encode("utf-8")

    def getitem(key):
        if key is _Dot11:
            return dot11_layer
        return dot11elt_layer

    pkt.__getitem__ = MagicMock(side_effect=getitem)

    # Signal attribute
    pkt.dBm_AntSignal = signal_dbm

    return pkt


# ---------------------------------------------------------------------------
# ProbeMonitor init
# ---------------------------------------------------------------------------

class TestProbeMonitorInit:
    """Tests for ProbeMonitor.__init__."""

    def test_probe_monitor_init(self):
        pm = ProbeMonitor(interface="wlan0mon")
        assert pm.interface == "wlan0mon"
        assert pm.verbose is False
        assert pm.json_output is False
        assert pm.use_color is True
        assert pm.channel_hop is True
        assert pm.hop_interval == 0.25
        assert pm.fixed_channel is None
        assert pm.output_writer is None
        assert isinstance(pm.probes, defaultdict)
        assert pm.bands == "2.4"

    def test_probe_monitor_custom_args(self):
        pm = ProbeMonitor(
            interface="wlan1",
            verbose=True,
            json_output=True,
            use_color=False,
            channel_hop=False,
            hop_interval=1.0,
            fixed_channel=6,
        )
        assert pm.interface == "wlan1"
        assert pm.verbose is True
        assert pm.json_output is True
        assert pm.use_color is False
        assert pm.channel_hop is False
        assert pm.hop_interval == 1.0
        assert pm.fixed_channel == 6


# ---------------------------------------------------------------------------
# ProbeMonitor.packet_handler
# ---------------------------------------------------------------------------

class TestPacketHandler:
    """Tests for ProbeMonitor.packet_handler."""

    def test_probe_monitor_packet_handler(self, capsys):
        """A valid probe request should be recorded and printed."""
        pm = ProbeMonitor(interface="wlan0mon", use_color=False)
        pkt = _make_probe_packet(client_mac="AA:BB:CC:DD:EE:FF", ssid="MyNetwork")
        pm.packet_handler(pkt)

        assert "AA:BB:CC:DD:EE:FF" in pm.probes
        assert "MyNetwork" in pm.probes["AA:BB:CC:DD:EE:FF"]

    def test_probe_monitor_duplicate_tracking(self, capsys):
        """Same MAC+SSID pair should only be added to the set once."""
        pm = ProbeMonitor(interface="wlan0mon", use_color=False)
        pkt = _make_probe_packet(client_mac="11:22:33:44:55:66", ssid="DuplicateSSID")

        pm.packet_handler(pkt)
        pm.packet_handler(pkt)  # second call

        assert len(pm.probes["11:22:33:44:55:66"]) == 1

    def test_probe_monitor_empty_ssid(self, capsys):
        """Broadcast probes (empty SSID) should be skipped."""
        pm = ProbeMonitor(interface="wlan0mon", use_color=False)
        pkt = _make_probe_packet(client_mac="AA:BB:CC:DD:EE:FF", ssid="")
        pm.packet_handler(pkt)

        # Empty SSID means nothing should be stored
        assert len(pm.probes["AA:BB:CC:DD:EE:FF"]) == 0

    def test_packet_handler_non_probe(self):
        """Packets that are not probe requests should be ignored."""
        pm = ProbeMonitor(interface="wlan0mon", use_color=False)
        pkt = MagicMock()
        pkt.haslayer.return_value = False

        pm.packet_handler(pkt)
        assert len(pm.probes) == 0


# ---------------------------------------------------------------------------
# Channel Hopper
# ---------------------------------------------------------------------------

class TestChannelHopper:
    """Tests for _channel_hop_loop and _set_channel."""

    @patch("hoover.subprocess.run")
    def test_channel_hopper_cycles(self, mock_run):
        """Channel hopper should iterate through channels 1-13."""
        pm = ProbeMonitor(interface="wlan0mon")
        channels_set = []

        def capture_channel(*args, **kwargs):
            # args[0] is the command list: ['iwconfig', iface, 'channel', '<n>']
            ch = int(args[0][3])
            channels_set.append(ch)
            if len(channels_set) >= 13:
                pm._hop_stop.set()

        mock_run.side_effect = capture_channel
        pm._channel_hop_loop()

        # Should have cycled through 1..13
        assert channels_set == list(range(1, 14))

    @patch("hoover.subprocess.run")
    def test_channel_hopper_custom_bands(self, mock_run):
        """Channel hopper should use the 5 GHz channel list when configured."""
        pm = ProbeMonitor(interface="wlan0mon", bands="5")
        channels_set = []

        def capture_channel(*args, **kwargs):
            ch = int(args[0][3])
            channels_set.append(ch)
            if len(channels_set) >= 1:
                pm._hop_stop.set()

        mock_run.side_effect = capture_channel
        pm._channel_hop_loop()

        assert channels_set == [36]


# ---------------------------------------------------------------------------
# OutputWriter — CSV
# ---------------------------------------------------------------------------

class TestCSVOutput:
    """Tests for CSV output."""

    def test_csv_output(self, tmp_path):
        csv_path = str(tmp_path / "output.csv")
        logger = MagicMock()
        writer = OutputWriter(csv_path, logger)
        writer.write("2024-01-01 12:00:00", "AA:BB:CC:DD:EE:FF",
                      "Apple", "TestSSID", -50)
        writer.close()

        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = list(csv.reader(f))

        # Header row
        assert reader[0] == ["timestamp", "client_mac", "vendor", "ssid", "signal_dbm"]
        # Data row
        assert reader[1][0] == "2024-01-01 12:00:00"
        assert reader[1][1] == "AA:BB:CC:DD:EE:FF"
        assert reader[1][2] == "Apple"
        assert reader[1][3] == "TestSSID"
        assert reader[1][4] == "-50"


# ---------------------------------------------------------------------------
# OutputWriter — JSON
# ---------------------------------------------------------------------------

class TestJSONOutput:
    """Tests for JSON-lines output."""

    def test_json_output(self, tmp_path):
        json_path = str(tmp_path / "output.json")
        logger = MagicMock()
        writer = OutputWriter(json_path, logger)
        writer.write("2024-01-01 12:00:00", "AA:BB:CC:DD:EE:FF",
                      "Apple", "TestSSID", -50)
        writer.write("2024-01-01 12:00:01", "11:22:33:44:55:66",
                      "Intel", "OtherSSID", -65)
        writer.close()

        with open(json_path, encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        assert len(lines) == 2
        assert lines[0]["client_mac"] == "AA:BB:CC:DD:EE:FF"
        assert lines[0]["ssid"] == "TestSSID"
        assert lines[1]["vendor"] == "Intel"


# ---------------------------------------------------------------------------
# OutputWriter — SQLite
# ---------------------------------------------------------------------------

class TestSQLiteOutput:
    """Tests for SQLite output."""

    def test_sqlite_output(self, tmp_path):
        db_path = str(tmp_path / "output.db")
        logger = MagicMock()
        writer = OutputWriter(db_path, logger)
        writer.write("2024-01-01 12:00:00", "AA:BB:CC:DD:EE:FF",
                      "Apple", "TestSSID", -50)
        writer.close()

        conn = sqlite3.connect(db_path)
        rows = conn.execute("SELECT * FROM probes").fetchall()
        conn.close()

        assert len(rows) == 1
        # (id, timestamp, client_mac, vendor, ssid, signal_dbm)
        assert rows[0][1] == "2024-01-01 12:00:00"
        assert rows[0][2] == "AA:BB:CC:DD:EE:FF"
        assert rows[0][3] == "Apple"
        assert rows[0][4] == "TestSSID"
        assert rows[0][5] == -50

    def test_sqlite_schema_indexes(self, tmp_path):
        db_path = str(tmp_path / "schema.db")
        logger = MagicMock()
        writer = OutputWriter(db_path, logger)
        writer.close()

        conn = sqlite3.connect(db_path)
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
        index_names = {row[0] for row in indexes}
        conn.close()

        assert "idx_probes_client_mac" in index_names
        assert "idx_probes_ssid" in index_names


# ---------------------------------------------------------------------------
# Color output
# ---------------------------------------------------------------------------

class TestColorOutput:
    """Tests for _color helper."""

    def test_color_output_enabled(self):
        result = _color("green", "hello", use_color=True)
        assert "\033[32m" in result
        assert "\033[0m" in result
        assert "hello" in result

    def test_color_output_disabled(self):
        result = _color("green", "hello", use_color=False)
        assert result == "hello"
        assert "\033[" not in result

    def test_color_unknown_name(self):
        result = _color("nonexistent", "text", use_color=True)
        # Unknown color should still include reset and text
        assert "text" in result
