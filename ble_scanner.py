#!/usr/bin/env python3
"""
BLE Scanner for Hoover WiFi Security Toolkit
Bluetooth Low Energy device discovery and GATT service enumeration
For authorized security testing and research only
"""

import argparse
import asyncio
import csv
import json
import os
import time
from typing import Optional

from bleak import BleakClient, BleakScanner

from oui_lookup import lookup_vendor
from utils import setup_logging


class BLEScanner:
    def __init__(
        self,
        scan_time: float = 10.0,
        service_scan: bool = False,
        filter_name: Optional[str] = None,
        filter_rssi: Optional[int] = None,
        output_file: Optional[str] = None,
    ) -> None:
        self.scan_time: float = scan_time
        self.service_scan: bool = service_scan
        self.filter_name: Optional[str] = filter_name
        self.filter_rssi: Optional[int] = filter_rssi
        self.output_file: Optional[str] = output_file
        self.logger = setup_logging("ble_scanner")
        self.devices: list[dict] = []
        self._stats: dict = {
            "devices_found": 0,
            "devices_filtered": 0,
            "services_enumerated": 0,
            "scan_time": 0.0,
        }

    async def _async_scan(self) -> list:
        devices = await BleakScanner.discover(timeout=self.scan_time)
        return devices

    def scan(self) -> list[dict]:
        self.logger.info("Scanning for BLE devices (%.1fs)...", self.scan_time)
        start = time.time()

        try:
            raw_devices = asyncio.run(self._async_scan())
        except Exception as e:
            self.logger.error("BLE scan failed: %s", e)
            return []

        results = []
        for device in raw_devices:
            vendor = self._lookup_vendor(device.address)
            entry = {
                "address": device.address,
                "name": device.name or "",
                "rssi": getattr(device, "rssi", None),
                "vendor": vendor,
                "metadata": {},
            }
            if hasattr(device, "metadata") and device.metadata:
                entry["metadata"] = {
                    k: v
                    for k, v in device.metadata.items()
                    if isinstance(v, (str, int, float, bool, list))
                }
            results.append(entry)

        self._stats["devices_found"] = len(results)
        self._stats["scan_time"] = round(time.time() - start, 2)

        results = self._apply_filters(results)
        self._stats["devices_filtered"] = len(results)

        self.devices = results
        self.logger.info("Found %d BLE devices", len(results))
        return results

    async def _async_get_services(self, address: str) -> list[dict]:
        services = []
        async with BleakClient(address) as client:
            for service in client.services:
                svc = {
                    "uuid": str(service.uuid),
                    "description": service.description or "",
                    "characteristics": [],
                }
                for char in service.characteristics:
                    svc["characteristics"].append(
                        {
                            "uuid": str(char.uuid),
                            "description": char.description or "",
                            "properties": list(char.properties),
                        }
                    )
                services.append(svc)
        return services

    def get_services(self, address: str) -> list[dict]:
        self.logger.info("Enumerating GATT services for %s...", address)
        try:
            services = asyncio.run(self._async_get_services(address))
            self._stats["services_enumerated"] += 1
            self.logger.info("Found %d services for %s", len(services), address)
            return services
        except Exception as e:
            self.logger.warning("Could not enumerate services for %s: %s", address, e)
            return []

    def _lookup_vendor(self, address: str) -> str:
        if ":" in address and len(address) == 17:
            return lookup_vendor(address)
        return "Unknown"

    def _apply_filters(self, devices: list[dict]) -> list[dict]:
        filtered = devices

        if self.filter_name:
            name_lower = self.filter_name.lower()
            filtered = [d for d in filtered if name_lower in (d.get("name") or "").lower()]

        if self.filter_rssi is not None:
            filtered = [d for d in filtered if (d.get("rssi") or -100) >= self.filter_rssi]

        return filtered

    def save_results(self, results: list[dict]) -> None:
        if not self.output_file or not results:
            return

        os.makedirs(os.path.dirname(self.output_file) or ".", exist_ok=True)
        ext = os.path.splitext(self.output_file)[1].lower()

        if ext == ".csv":
            with open(self.output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["address", "name", "rssi", "vendor"])
                for d in results:
                    writer.writerow([d["address"], d["name"], d.get("rssi", ""), d["vendor"]])
        else:
            with open(self.output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)

        self.logger.info("Results saved to %s", self.output_file)

    def print_results(self, results: list[dict]) -> None:
        if not results:
            self.logger.info("No BLE devices found")
            return

        print(f"\n{'=' * 80}")
        print(f"{'Address':<20} {'Name':<25} {'RSSI':<8} {'Vendor'}")
        print(f"{'=' * 80}")

        for d in sorted(results, key=lambda x: x.get("rssi") or -100, reverse=True):
            rssi_str = f"{d['rssi']}dBm" if d.get("rssi") is not None else "?"
            print(
                f"{d['address']:<20} {(d['name'] or '<unnamed>'):<25} {rssi_str:<8} {d['vendor']}"
            )

        print(f"\nTotal: {len(results)} devices found")

    def get_stats(self) -> dict:
        return dict(self._stats)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BLE Scanner - Discover Bluetooth Low Energy devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic BLE scan
  python3 ble_scanner.py

  # Longer scan with service enumeration
  python3 ble_scanner.py -t 30 --services

  # Filter by name and minimum RSSI
  python3 ble_scanner.py --filter-name "Smart" --filter-rssi -70

  # Save results to JSON
  python3 ble_scanner.py -t 15 -o ble_devices.json

Note: BLE scanning usually does not require root.
      For authorized security testing only.
        """,
    )

    parser.add_argument(
        "-t", "--time", type=float, default=10.0, help="Scan duration in seconds (default: 10.0)"
    )
    parser.add_argument(
        "--services", action="store_true", help="Enumerate GATT services for each device"
    )
    parser.add_argument("--filter-name", help="Filter by device name (case-insensitive substring)")
    parser.add_argument("--filter-rssi", type=int, help="Minimum RSSI threshold (e.g. -70)")
    parser.add_argument("-o", "--output", help="Output file (.json or .csv)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    scanner = BLEScanner(
        scan_time=args.time,
        service_scan=args.services,
        filter_name=args.filter_name,
        filter_rssi=args.filter_rssi,
        output_file=args.output,
    )

    results = scanner.scan()

    if args.services and results:
        for device in results:
            services = scanner.get_services(device["address"])
            device["services"] = services

    scanner.print_results(results)
    scanner.save_results(results)


if __name__ == "__main__":
    main()
