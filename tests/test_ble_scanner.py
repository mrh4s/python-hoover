"""Tests for ble_scanner.py — BLE Device Scanner."""

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

sys.modules.setdefault("bleak", MagicMock())

from ble_scanner import BLEScanner  # noqa: E402


@pytest.fixture
def scanner():
    return BLEScanner()


@pytest.fixture
def scanner_with_filters():
    return BLEScanner(filter_name="Smart", filter_rssi=-70)


class TestBLEScannerInit:
    def test_default_init(self):
        s = BLEScanner()
        assert s.scan_time == 10.0
        assert s.service_scan is False
        assert s.filter_name is None
        assert s.filter_rssi is None
        assert s.output_file is None
        assert s.devices == []

    def test_custom_init(self):
        s = BLEScanner(
            scan_time=30.0,
            service_scan=True,
            filter_name="Beacon",
            filter_rssi=-60,
            output_file="ble.json",
        )
        assert s.scan_time == 30.0
        assert s.service_scan is True
        assert s.filter_name == "Beacon"
        assert s.filter_rssi == -60
        assert s.output_file == "ble.json"


class TestScan:
    @patch("ble_scanner.asyncio.run")
    @patch("ble_scanner.lookup_vendor", return_value="TestVendor")
    def test_scan_returns_devices(self, mock_vendor, mock_asyncio, scanner):
        mock_device = MagicMock()
        mock_device.address = "AA:BB:CC:DD:EE:FF"
        mock_device.name = "SmartLight"
        mock_device.rssi = -55
        mock_device.metadata = {}
        mock_asyncio.return_value = [mock_device]

        results = scanner.scan()
        assert len(results) == 1
        assert results[0]["address"] == "AA:BB:CC:DD:EE:FF"
        assert results[0]["name"] == "SmartLight"
        assert results[0]["rssi"] == -55
        assert results[0]["vendor"] == "TestVendor"

    @patch("ble_scanner.asyncio.run")
    def test_scan_empty(self, mock_asyncio, scanner):
        mock_asyncio.return_value = []
        results = scanner.scan()
        assert results == []

    @patch("ble_scanner.asyncio.run", side_effect=Exception("BLE error"))
    def test_scan_error(self, mock_asyncio, scanner):
        results = scanner.scan()
        assert results == []

    @patch("ble_scanner.asyncio.run")
    @patch("ble_scanner.lookup_vendor", return_value="Unknown")
    def test_scan_no_name(self, mock_vendor, mock_asyncio, scanner):
        mock_device = MagicMock()
        mock_device.address = "11:22:33:44:55:66"
        mock_device.name = None
        mock_device.rssi = -80
        mock_device.metadata = {}
        mock_asyncio.return_value = [mock_device]

        results = scanner.scan()
        assert results[0]["name"] == ""


class TestGetServices:
    @patch("ble_scanner.asyncio.run")
    def test_get_services(self, mock_asyncio, scanner):
        mock_service = MagicMock()
        mock_service.uuid = "0000180a-0000-1000-8000-00805f9b34fb"
        mock_service.description = "Device Information"
        mock_char = MagicMock()
        mock_char.uuid = "00002a29-0000-1000-8000-00805f9b34fb"
        mock_char.description = "Manufacturer Name"
        mock_char.properties = ["read"]
        mock_service.characteristics = [mock_char]

        mock_asyncio.return_value = [
            {
                "uuid": str(mock_service.uuid),
                "description": mock_service.description,
                "characteristics": [
                    {
                        "uuid": str(mock_char.uuid),
                        "description": mock_char.description,
                        "properties": list(mock_char.properties),
                    }
                ],
            }
        ]

        services = scanner.get_services("AA:BB:CC:DD:EE:FF")
        assert len(services) == 1

    @patch("ble_scanner.asyncio.run", side_effect=Exception("Connection failed"))
    def test_get_services_error(self, mock_asyncio, scanner):
        services = scanner.get_services("AA:BB:CC:DD:EE:FF")
        assert services == []


class TestFilters:
    def test_filter_by_name(self):
        s = BLEScanner(filter_name="Smart")
        devices = [
            {"name": "SmartLight", "rssi": -50, "address": "AA:BB:CC:DD:EE:FF"},
            {"name": "HeadPhones", "rssi": -60, "address": "11:22:33:44:55:66"},
            {"name": "SmartPlug", "rssi": -70, "address": "22:33:44:55:66:77"},
        ]
        filtered = s._apply_filters(devices)
        assert len(filtered) == 2

    def test_filter_by_rssi(self):
        s = BLEScanner(filter_rssi=-65)
        devices = [
            {"name": "Device1", "rssi": -50, "address": "AA:BB:CC:DD:EE:FF"},
            {"name": "Device2", "rssi": -70, "address": "11:22:33:44:55:66"},
            {"name": "Device3", "rssi": -60, "address": "22:33:44:55:66:77"},
        ]
        filtered = s._apply_filters(devices)
        assert len(filtered) == 2

    def test_filter_combined(self):
        s = BLEScanner(filter_name="Smart", filter_rssi=-65)
        devices = [
            {"name": "SmartLight", "rssi": -50, "address": "AA:BB:CC:DD:EE:FF"},
            {"name": "SmartPlug", "rssi": -80, "address": "11:22:33:44:55:66"},
            {"name": "Phone", "rssi": -40, "address": "22:33:44:55:66:77"},
        ]
        filtered = s._apply_filters(devices)
        assert len(filtered) == 1
        assert filtered[0]["name"] == "SmartLight"

    def test_no_filters(self, scanner):
        devices = [{"name": "A", "rssi": -50}, {"name": "B", "rssi": -90}]
        filtered = scanner._apply_filters(devices)
        assert len(filtered) == 2

    def test_filter_name_case_insensitive(self):
        s = BLEScanner(filter_name="smart")
        devices = [{"name": "SmartLight", "rssi": -50, "address": "AA:BB:CC:DD:EE:FF"}]
        filtered = s._apply_filters(devices)
        assert len(filtered) == 1


class TestVendorLookup:
    @patch("ble_scanner.lookup_vendor", return_value="Apple")
    def test_lookup_with_mac(self, mock_lookup, scanner):
        result = scanner._lookup_vendor("AA:BB:CC:DD:EE:FF")
        assert result == "Apple"

    def test_lookup_without_mac(self, scanner):
        result = scanner._lookup_vendor("short")
        assert result == "Unknown"


class TestSaveResults:
    def test_save_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "ble.json")
            s = BLEScanner(output_file=filepath)
            results = [{"address": "AA:BB:CC:DD:EE:FF", "name": "Test", "rssi": -50, "vendor": "V"}]
            s.save_results(results)
            assert os.path.exists(filepath)
            with open(filepath) as f:
                data = json.load(f)
            assert len(data) == 1

    def test_save_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "ble.csv")
            s = BLEScanner(output_file=filepath)
            results = [{"address": "AA:BB:CC:DD:EE:FF", "name": "Test", "rssi": -50, "vendor": "V"}]
            s.save_results(results)
            assert os.path.exists(filepath)

    def test_save_empty(self, scanner):
        scanner.output_file = "test.json"
        scanner.save_results([])

    def test_save_no_output(self, scanner):
        scanner.save_results([{"test": True}])


class TestPrintResults:
    def test_print_with_devices(self, scanner, capsys):
        results = [
            {"address": "AA:BB:CC:DD:EE:FF", "name": "SmartLight", "rssi": -50, "vendor": "TestCo"},
        ]
        scanner.print_results(results)
        output = capsys.readouterr().out
        assert "SmartLight" in output
        assert "AA:BB:CC:DD:EE:FF" in output

    def test_print_empty(self, scanner, capsys):
        scanner.print_results([])


class TestGetStats:
    def test_initial_stats(self, scanner):
        stats = scanner.get_stats()
        assert stats["devices_found"] == 0
        assert stats["devices_filtered"] == 0
        assert stats["services_enumerated"] == 0
        assert stats["scan_time"] == 0.0
