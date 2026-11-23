"""Tests for ble_attack.py — BLE GATT attack module."""

import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Mock bleak before importing the module under test (no scapy used here)
sys.modules.setdefault("bleak", MagicMock())

from ble_attack import (  # noqa: E402
    DEFAULT_FUZZ_PATTERNS,
    SUPPORTED_MODES,
    BLEAttack,
    main,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def attack(tmp_path):
    return BLEAttack(
        target_address="AA:BB:CC:DD:EE:FF",
        attack_mode="scan",
        scan_time=5.0,
        output_dir=str(tmp_path / "captures"),
        timeout=60,
    )


def _make_mock_device(address="AA:BB:CC:DD:EE:FF", name="TestDevice", rssi=-60):
    device = MagicMock()
    device.address = address
    device.name = name
    device.rssi = rssi
    return device


def _make_mock_adv(rssi=-60, local_name="TestDevice", service_uuids=None, manufacturer_data=None):
    adv = MagicMock()
    adv.rssi = rssi
    adv.local_name = local_name
    adv.service_uuids = service_uuids or ["0000180a-0000-1000-8000-00805f9b34fb"]
    adv.manufacturer_data = manufacturer_data or {76: b"\x01\x02\x03"}
    return adv


def _make_mock_characteristic(uuid, description="", properties=None, descriptors=None):
    char = MagicMock()
    char.uuid = uuid
    char.description = description
    char.properties = properties or ["read", "write"]
    char.descriptors = descriptors or []
    return char


def _make_mock_service(uuid, description="", characteristics=None):
    service = MagicMock()
    service.uuid = uuid
    service.description = description
    service.characteristics = characteristics or []
    return service


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestInit:
    def test_init_defaults(self):
        """Verify default parameters."""
        attack = BLEAttack()
        assert attack.target_address is None
        assert attack.attack_mode == "scan"
        assert attack.scan_time == 10.0
        assert attack.output_dir == "captures"
        assert attack.timeout == 120
        assert attack.devices == []
        assert attack.gatt_map == {}
        assert attack.notifications == []


class TestAdvertisementParsing:
    def test_parse_advertisement(self, attack):
        """Mock BleakScanner device, verify parsed fields."""
        device = _make_mock_device()
        adv = _make_mock_adv()

        parsed = attack._parse_advertisement(device, adv)

        assert parsed["address"] == "AA:BB:CC:DD:EE:FF"
        assert parsed["local_name"] == "TestDevice"
        assert parsed["rssi"] == -60
        assert "0000180a-0000-1000-8000-00805f9b34fb" in parsed["service_uuids"]
        assert "76" in parsed["manufacturer_data"]
        assert parsed["manufacturer_data"]["76"] == "010203"


class TestGattEnumeration:
    def test_enumerate_gatt_structure(self, attack):
        """Mock BleakClient services, verify enumeration dict."""
        char = _make_mock_characteristic(
            "00002a29-0000-1000-8000-00805f9b34fb",
            description="Manufacturer Name String",
            properties=["read"],
        )
        service = _make_mock_service(
            "0000180a-0000-1000-8000-00805f9b34fb",
            description="Device Information",
            characteristics=[char],
        )

        mock_client = MagicMock()
        mock_client.services = [service]
        mock_client.read_gatt_char = AsyncMock(return_value=b"ExampleCorp")
        attack._client = mock_client

        result = attack.enumerate_gatt()

        assert "services" in result
        assert len(result["services"]) == 1
        svc = result["services"][0]
        assert svc["uuid"] == "0000180a-0000-1000-8000-00805f9b34fb"
        assert svc["description"] == "Device Information"
        assert len(svc["characteristics"]) == 1
        char_entry = svc["characteristics"][0]
        assert char_entry["uuid"] == "00002a29-0000-1000-8000-00805f9b34fb"
        assert char_entry["properties"] == ["read"]
        assert char_entry["value"] == "ExampleCorp"

    def test_enumerate_gatt_not_connected(self, attack):
        """No client connected returns empty services list."""
        attack._client = None
        result = attack.enumerate_gatt()
        assert result == {"services": []}


class TestReadWrite:
    def test_read_characteristic(self, attack):
        """Mock successful read, verify bytes returned."""
        mock_client = MagicMock()
        mock_client.read_gatt_char = AsyncMock(return_value=bytearray(b"\x01\x02\x03"))
        attack._client = mock_client

        result = attack.read_characteristic("0000ffe1-0000-1000-8000-00805f9b34fb")

        assert result == b"\x01\x02\x03"
        assert isinstance(result, bytes)

    def test_read_characteristic_not_connected(self, attack):
        attack._client = None
        result = attack.read_characteristic("0000ffe1-0000-1000-8000-00805f9b34fb")
        assert result == b""

    def test_write_characteristic(self, attack):
        """Mock successful write, verify True returned."""
        mock_client = MagicMock()
        mock_client.write_gatt_char = AsyncMock(return_value=None)
        attack._client = mock_client

        result = attack.write_characteristic(
            "0000ffe1-0000-1000-8000-00805f9b34fb", b"\xde\xad\xbe\xef", response=True
        )

        assert result is True
        assert len(attack.write_log) == 1
        assert attack.write_log[0]["uuid"] == "0000ffe1-0000-1000-8000-00805f9b34fb"
        assert attack.write_log[0]["data"] == "deadbeef"

    def test_write_characteristic_failure(self, attack):
        mock_client = MagicMock()
        mock_client.write_gatt_char = AsyncMock(side_effect=Exception("write failed"))
        attack._client = mock_client

        result = attack.write_characteristic("0000ffe1-0000-1000-8000-00805f9b34fb", b"\x01")
        assert result is False


class TestReplay:
    def test_replay_write_count(self, attack):
        """Mock write, verify called N times."""
        with patch.object(attack, "write_characteristic", return_value=True) as mock_write:
            with patch("ble_attack.time.sleep"):
                attack._replay_write(
                    "0000ffe1-0000-1000-8000-00805f9b34fb", b"\xde\xad", count=5, interval=0.1
                )

        assert mock_write.call_count == 5
        mock_write.assert_called_with("0000ffe1-0000-1000-8000-00805f9b34fb", b"\xde\xad")


class TestNotifications:
    def test_capture_notifications(self, attack):
        """Mock notification callback, verify data captured."""
        mock_client = MagicMock()

        async def fake_start_notify(uuid, callback):
            callback("sender", b"\x01\x02")
            callback("sender", b"\x03\x04")

        mock_client.start_notify = AsyncMock(side_effect=fake_start_notify)
        mock_client.stop_notify = AsyncMock(return_value=None)
        attack._client = mock_client

        with patch("ble_attack.asyncio.sleep", new=AsyncMock(return_value=None)):
            result = attack.capture_notifications(
                "0000ffe2-0000-1000-8000-00805f9b34fb", duration=1.0
            )

        assert result == [b"\x01\x02", b"\x03\x04"]
        assert attack.notifications == [b"\x01\x02", b"\x03\x04"]

    def test_capture_notifications_not_connected(self, attack):
        attack._client = None
        result = attack.capture_notifications("0000ffe2-0000-1000-8000-00805f9b34fb")
        assert result == []


class TestFuzzing:
    def test_fuzz_characteristic_patterns(self, attack):
        """Verify fuzz patterns generated and sent."""
        with patch.object(attack, "write_characteristic", return_value=True) as mock_write:
            results = attack._fuzz_characteristic("0000ffe1-0000-1000-8000-00805f9b34fb")

        assert mock_write.call_count == len(DEFAULT_FUZZ_PATTERNS)
        assert len(results) == len(DEFAULT_FUZZ_PATTERNS)
        for entry in results:
            assert entry["uuid"] == "0000ffe1-0000-1000-8000-00805f9b34fb"
            assert entry["success"] is True
        assert len(attack.fuzz_results) == len(DEFAULT_FUZZ_PATTERNS)

    def test_fuzz_characteristic_custom_patterns(self, attack):
        patterns = [b"\x00", b"\xff\xff"]
        with patch.object(attack, "write_characteristic", return_value=False) as mock_write:
            results = attack._fuzz_characteristic(
                "0000ffe1-0000-1000-8000-00805f9b34fb", patterns=patterns
            )

        assert mock_write.call_count == 2
        assert results[0]["pattern"] == "00"
        assert results[1]["pattern"] == "ffff"
        assert all(r["success"] is False for r in results)


class TestConnection:
    def test_connect_device_timeout(self, attack):
        """Mock connection timeout, verify handled."""
        with patch("ble_attack.asyncio.run", side_effect=Exception("connection timeout")):
            result = attack.connect_device("AA:BB:CC:DD:EE:FF")

        assert result is False
        assert attack._connected is False

    def test_connect_device_success(self, attack):
        with patch("ble_attack.asyncio.run", return_value=True):
            result = attack.connect_device("AA:BB:CC:DD:EE:FF")

        assert result is True
        assert attack._connected is True
        assert attack.target_address == "AA:BB:CC:DD:EE:FF"

    def test_disconnect_device(self, attack):
        """Verify disconnect called."""
        mock_client = MagicMock()
        attack._client = mock_client
        attack._connected = True

        with patch("ble_attack.asyncio.run") as mock_run:
            attack.disconnect_device()

        mock_run.assert_called_once()
        assert attack._connected is False

    def test_disconnect_device_no_client(self, attack):
        attack._client = None
        # Should not raise even without a connection established.
        attack.disconnect_device()
        assert attack._connected is False


class TestSaveResults:
    def test_save_results_json(self, attack, tmp_path):
        """Verify JSON output file."""
        attack.devices = [{"address": "AA:BB:CC:DD:EE:FF", "name": "Test"}]
        attack.notifications = [b"\x01\x02"]

        filepath = attack.save_results()

        assert filepath is not None
        assert os.path.exists(filepath)
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        assert data["target_address"] == "AA:BB:CC:DD:EE:FF"
        assert data["devices"][0]["address"] == "AA:BB:CC:DD:EE:FF"
        assert data["notifications"] == ["0102"]


class TestStatus:
    def test_get_status(self, attack):
        """Verify status fields."""
        status = attack.get_status()

        assert "running" in status
        assert "connected" in status
        assert status["target_address"] == "AA:BB:CC:DD:EE:FF"
        assert status["attack_mode"] == "scan"
        assert status["devices_found"] == 0
        assert status["notifications_captured"] == 0
        assert status["timeout"] == 60


class TestCLI:
    def test_cli_mode_choices(self):
        """Verify mode validation."""
        assert "scan" in SUPPORTED_MODES
        assert "enumerate" in SUPPORTED_MODES
        assert "replay" in SUPPORTED_MODES
        assert "spoof" in SUPPORTED_MODES
        assert "fuzz" in SUPPORTED_MODES

        with patch("sys.argv", ["ble_attack.py", "-m", "invalid_mode"]):
            with pytest.raises(SystemExit):
                main()

    def test_cli_uuid_required_for_replay(self, tmp_path):
        """Verify UUID required when mode=replay."""
        with patch(
            "sys.argv",
            [
                "ble_attack.py",
                "-m",
                "replay",
                "--target",
                "AA:BB:CC:DD:EE:FF",
                "-o",
                str(tmp_path),
            ],
        ):
            with pytest.raises(SystemExit):
                main()

    def test_cli_target_required_for_replay(self, tmp_path):
        """Verify --target is required for replay mode too."""
        with patch(
            "sys.argv",
            [
                "ble_attack.py",
                "-m",
                "replay",
                "--uuid",
                "0000ffe1-0000-1000-8000-00805f9b34fb",
                "-o",
                str(tmp_path),
            ],
        ):
            with pytest.raises(SystemExit):
                main()
