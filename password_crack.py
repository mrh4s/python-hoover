#!/usr/bin/env python3
"""
Password Cracking Integration for Hoover WiFi Security Toolkit
Automates the handshake -> password cracking pipeline using hashcat
and aircrack-ng. Takes a captured .pcap/.cap file or a hashcat .22000
file, detects its format, and runs the appropriate cracking tool with
configurable wordlists and rules.

For authorized security testing and research only.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Optional

from utils import setup_logging, validate_mac

# hashcat hash-mode numbers used by this module.
HASHCAT_MODE_WPA_22000 = 22000   # WPA-PBKDF2-PMKID+EAPOL (.22000 / hc22000)
HASHCAT_MODE_WPA_LEGACY = 2500   # Legacy WPA/WPA2 (.hccapx)
HASHCAT_MODE_WEP = 13100         # WEP (per module convention)

_HASHCAT_MODE_BY_FORMAT = {
    "hc22000": HASHCAT_MODE_WPA_22000,
    "hccapx": HASHCAT_MODE_WPA_LEGACY,
    "wep": HASHCAT_MODE_WEP,
}

# Capture formats that aircrack-ng can read directly.
_AIRCRACK_NATIVE_FORMATS = {"pcap", "pcapng", "cap"}


class PasswordCracker:
    """Automate hashcat / aircrack-ng password cracking of WiFi captures."""

    def __init__(self, capture_file: str,
                 target_bssid: Optional[str] = None,
                 wordlist: str = "/usr/share/wordlists/rockyou.txt",
                 tool: str = "auto",
                 hashcat_mode: Optional[int] = None,
                 rules_file: Optional[str] = None,
                 output_dir: str = "crack_results",
                 timeout: int = 3600,
                 gpu: bool = True) -> None:
        self.capture_file: str = capture_file
        self.target_bssid: Optional[str] = None
        if target_bssid:
            if not validate_mac(target_bssid):
                raise ValueError(f"Invalid BSSID format: {target_bssid!r}")
            self.target_bssid = target_bssid.upper()

        self.wordlist: str = wordlist
        self.tool: str = tool
        self.hashcat_mode: Optional[int] = hashcat_mode
        self.rules_file: Optional[str] = rules_file
        self.output_dir: str = output_dir
        self.timeout: int = timeout
        self.gpu: bool = gpu

        self.logger = setup_logging("password_crack")

        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._result: dict = {
            "status": "idle",
            "tool": None,
            "cracked": False,
            "password": None,
            "speed": None,
            "progress": None,
            "recovered": None,
            "start_time": None,
            "end_time": None,
        }

    # ------------------------------------------------------------------
    # Tool / format detection
    # ------------------------------------------------------------------

    def check_tools(self) -> dict:
        """Check which cracking/conversion tools are installed."""
        tools = {
            "hashcat": shutil.which("hashcat") is not None,
            "aircrack": shutil.which("aircrack-ng") is not None,
            "hcxpcapngtool": shutil.which("hcxpcapngtool") is not None,
            "cap2hccapx": shutil.which("cap2hccapx") is not None,
        }
        for name, available in tools.items():
            self.logger.info("  %s: %s", name, "found" if available else "not found")
        return tools

    def detect_capture_format(self, filepath: str) -> str:
        """Detect the capture file's format.

        Returns one of: "pcap", "pcapng", "hc22000", "hccapx", "cap",
        or "unknown".
        """
        ext = os.path.splitext(filepath)[1].lower()

        if ext in (".22000", ".hc22000"):
            return "hc22000"
        if ext == ".hccapx":
            return "hccapx"
        if ext == ".pcapng":
            return "pcapng"
        if ext == ".cap":
            return "cap"
        if ext == ".pcap":
            return "pcap"

        # Fall back to sniffing magic bytes for ambiguous/extension-less files.
        try:
            with open(filepath, "rb") as f:
                magic = f.read(4)
        except OSError as e:
            self.logger.warning("Could not read %s to detect format: %s", filepath, e)
            return "unknown"

        if magic == b"\x0a\x0d\x0d\x0a":
            return "pcapng"
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
                     b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
            return "pcap"

        return "unknown"

    def is_wep_capture(self, filepath: str) -> bool:
        """Best-effort check for whether a capture contains WEP IVs.

        WEP captures are detected by extension (.ivs / .ivs2) or by the
        presence of "WEP" markers in a plaintext-adjacent header; this is
        a heuristic, not a full packet parse (no scapy dependency here).
        """
        ext = os.path.splitext(filepath)[1].lower()
        if ext in (".ivs", ".ivs2"):
            return True
        try:
            with open(filepath, "rb") as f:
                head = f.read(4096)
        except OSError:
            return False
        return b"WEP" in head

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    def convert_to_hashcat(self, pcap_path: str) -> Optional[str]:
        """Convert a pcap/pcapng/cap capture into a hashcat-ready file.

        Prefers hcxpcapngtool (produces .22000), falls back to
        cap2hccapx (produces .hccapx). Returns the output file path,
        or None if no converter is available or conversion failed.
        """
        os.makedirs(self.output_dir, exist_ok=True)
        basename = os.path.splitext(os.path.basename(pcap_path))[0]

        if shutil.which("hcxpcapngtool"):
            out_path = os.path.join(self.output_dir, f"{basename}.22000")
            cmd = ["hcxpcapngtool", "-o", out_path, pcap_path]
            self.logger.info("Converting with hcxpcapngtool: %s", " ".join(cmd))
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if proc.returncode == 0 and os.path.exists(out_path):
                    return out_path
                self.logger.warning("hcxpcapngtool failed: %s", proc.stderr.strip())
            except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as e:
                self.logger.error("hcxpcapngtool error: %s", e)

        if shutil.which("cap2hccapx"):
            out_path = os.path.join(self.output_dir, f"{basename}.hccapx")
            cmd = ["cap2hccapx", pcap_path, out_path]
            self.logger.info("Converting with cap2hccapx: %s", " ".join(cmd))
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if proc.returncode == 0 and os.path.exists(out_path):
                    return out_path
                self.logger.warning("cap2hccapx failed: %s", proc.stderr.strip())
            except (subprocess.TimeoutExpired, OSError, FileNotFoundError) as e:
                self.logger.error("cap2hccapx error: %s", e)

        self.logger.error("No hashcat converter (hcxpcapngtool/cap2hccapx) available")
        return None

    def convert_to_aircrack(self, filepath: str) -> Optional[str]:
        """Ensure the capture is in a format aircrack-ng can read directly.

        pcap/pcapng/cap files are returned unchanged. hc22000/hccapx
        files cannot be converted back to a packet capture, so None is
        returned.
        """
        fmt = self.detect_capture_format(filepath)
        if fmt in _AIRCRACK_NATIVE_FORMATS:
            return filepath

        self.logger.error(
            "Cannot use %s format with aircrack-ng (no packet capture available)", fmt
        )
        return None

    # ------------------------------------------------------------------
    # Cracking
    # ------------------------------------------------------------------

    def _select_tool(self) -> str:
        if self.tool in ("hashcat", "aircrack"):
            return self.tool

        # auto: prefer hashcat when GPU acceleration is requested and
        # hashcat is installed, otherwise fall back to aircrack-ng.
        has_hashcat = shutil.which("hashcat") is not None
        has_aircrack = shutil.which("aircrack-ng") is not None

        if self.gpu and has_hashcat:
            return "hashcat"
        if has_aircrack:
            return "aircrack"
        if has_hashcat:
            return "hashcat"
        return "hashcat"

    def start(self) -> dict:
        """Main entry point: detect format, convert if needed, and crack."""
        self._result["start_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._result["status"] = "running"

        if not os.path.exists(self.capture_file):
            self.logger.error("Capture file not found: %s", self.capture_file)
            self._result.update({"status": "error", "error": "file_not_found"})
            return dict(self._result)

        selected = self._select_tool()
        self.logger.info("Selected cracking tool: %s", selected)

        fmt = self.detect_capture_format(self.capture_file)
        self.logger.info("Detected capture format: %s", fmt)

        is_wep = self.is_wep_capture(self.capture_file)

        if selected == "hashcat":
            if fmt in ("hc22000", "hccapx"):
                hash_file = self.capture_file
            else:
                hash_file = self.convert_to_hashcat(self.capture_file)

            if hash_file:
                result = self.run_hashcat(hash_file)
            else:
                self.logger.warning("Falling back to aircrack-ng (conversion failed)")
                pcap_file = self.convert_to_aircrack(self.capture_file)
                if pcap_file:
                    result = self.run_aircrack(pcap_file)
                else:
                    result = {"status": "error", "error": "no_usable_tool", "cracked": False}
        else:
            pcap_file = self.convert_to_aircrack(self.capture_file)
            if pcap_file:
                result = self.run_aircrack(pcap_file, wep=is_wep)
            else:
                result = {"status": "error", "error": "no_usable_tool", "cracked": False}

        with self._lock:
            self._result.update(result)
            self._result["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self._save_results()
        return dict(self._result)

    def run_hashcat(self, hash_file: str) -> dict:
        """Run hashcat against a .22000/.hccapx hash file."""
        if not shutil.which("hashcat"):
            self.logger.error("hashcat not found")
            return {"status": "tool_not_found", "tool": "hashcat", "cracked": False}

        mode = self.hashcat_mode
        if mode is None:
            fmt = self.detect_capture_format(hash_file)
            mode = _HASHCAT_MODE_BY_FORMAT.get(fmt, HASHCAT_MODE_WPA_22000)

        potfile = os.path.join(self.output_dir, "hashcat.potfile")
        os.makedirs(self.output_dir, exist_ok=True)

        cmd = ["hashcat", "-m", str(mode), "-a", "0", hash_file, self.wordlist,
               "--potfile-path", potfile]
        if self.rules_file:
            cmd.extend(["-r", self.rules_file])
        cmd.extend(["-D", "2" if self.gpu else "1"])

        result = self._run_tool(cmd, "hashcat", self._parse_hashcat_output)
        result["tool"] = "hashcat"
        return result

    def run_aircrack(self, pcap_file: str, wep: Optional[bool] = None) -> dict:
        """Run aircrack-ng against a pcap/cap capture."""
        if not shutil.which("aircrack-ng"):
            self.logger.error("aircrack-ng not found")
            return {"status": "tool_not_found", "tool": "aircrack", "cracked": False}

        if wep is None:
            wep = self.is_wep_capture(pcap_file)

        cmd = ["aircrack-ng", "-a", "1" if wep else "2", "-w", self.wordlist]
        if self.target_bssid:
            cmd.extend(["-b", self.target_bssid])
        cmd.append(pcap_file)

        result = self._run_tool(cmd, "aircrack", self._parse_aircrack_output)
        result["tool"] = "aircrack"
        return result

    def _run_tool(self, cmd: list, tool_name: str, parse_func) -> dict:
        """Run a cracking subprocess, monitor its output and timeout."""
        self.logger.info("Running %s: %s", tool_name, " ".join(cmd))
        self._stop_event.clear()
        result = {"status": "not_cracked", "cracked": False, "password": None,
                  "output": ""}

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            self.logger.error("%s not found", tool_name)
            return {"status": "tool_not_found", "cracked": False, "password": None}
        except OSError as e:
            self.logger.error("Error starting %s: %s", tool_name, e)
            return {"status": "error", "error": str(e), "cracked": False, "password": None}

        output_lines: list = []
        start = time.time()
        timed_out = False

        try:
            while not self._stop_event.is_set():
                if time.time() - start > self.timeout:
                    self.logger.warning("Timeout reached (%ds)", self.timeout)
                    timed_out = True
                    break

                if self._process.poll() is not None:
                    break

                line = self._process.stdout.readline()
                if line:
                    decoded = line.decode("utf-8", errors="replace").strip() \
                        if isinstance(line, bytes) else str(line).strip()
                    if decoded:
                        output_lines.append(decoded)
                        with self._lock:
                            self._result["status"] = "running"

            remaining = self._process.stdout.read()
            if remaining:
                decoded = remaining.decode("utf-8", errors="replace") \
                    if isinstance(remaining, bytes) else str(remaining)
                for line in decoded.split("\n"):
                    line = line.strip()
                    if line:
                        output_lines.append(line)
        except Exception as e:
            self.logger.error("Error reading %s output: %s", tool_name, e)
        finally:
            if self._process and self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()

        full_output = "\n".join(output_lines)
        parsed = parse_func(full_output)
        result.update(parsed)
        result["output"] = full_output[-4000:]

        if timed_out:
            result["status"] = "timeout"
        elif parsed.get("cracked"):
            result["status"] = "cracked"
        else:
            result["status"] = "not_cracked"

        with self._lock:
            self._result.update(result)

        return result

    # ------------------------------------------------------------------
    # Output parsing
    # ------------------------------------------------------------------

    def _parse_hashcat_output(self, output: str) -> dict:
        """Parse hashcat stdout/--status output.

        Extracts status, speed, progress and the recovered password
        (if hashcat printed a cracked "hash:password" line).
        """
        result = {
            "status_text": None,
            "speed": None,
            "progress": None,
            "recovered": None,
            "password": None,
            "cracked": False,
        }
        if not output:
            return result

        status_match = re.search(r"Status\.*:\s*(.+)", output)
        if status_match:
            result["status_text"] = status_match.group(1).strip()

        speed_match = re.search(r"Speed\.#?\d*\.*:\s*(.+)", output)
        if speed_match:
            result["speed"] = speed_match.group(1).strip()

        progress_match = re.search(r"Progress\.*:\s*(.+)", output)
        if progress_match:
            result["progress"] = progress_match.group(1).strip()

        recovered_match = re.search(r"Recovered\.*:\s*(.+)", output)
        if recovered_match:
            result["recovered"] = recovered_match.group(1).strip()

        if result["status_text"] and result["status_text"].lower().startswith("cracked"):
            result["cracked"] = True

        # hashcat prints cracked results as "hash[*field*...]:password"
        for line in output.splitlines():
            line = line.strip()
            m = re.match(r"^[0-9a-fA-F*]{8,}(?:\*[^:\n]*)*:(.+)$", line)
            if m:
                result["password"] = m.group(1).strip()
                result["cracked"] = True

        return result

    def _parse_aircrack_output(self, output: str) -> dict:
        """Parse aircrack-ng stdout.

        Extracts tested/total keys, speed and the found password from
        the "KEY FOUND! [ ... ]" line.
        """
        result = {
            "tested_keys": None,
            "total_keys": None,
            "speed": None,
            "password": None,
            "cracked": False,
        }
        if not output:
            return result

        progress_match = re.search(
            r"(\d+)\s*/\s*(\d+)\s+keys tested\s*\(([\d.]+)\s*k/s\)", output
        )
        if progress_match:
            result["tested_keys"] = int(progress_match.group(1))
            result["total_keys"] = int(progress_match.group(2))
            result["speed"] = f"{progress_match.group(3)} k/s"

        key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", output)
        if key_match:
            result["password"] = key_match.group(1).strip()
            result["cracked"] = True

        return result

    # ------------------------------------------------------------------
    # Status / control
    # ------------------------------------------------------------------

    def get_status(self) -> dict:
        with self._lock:
            return dict(self._result)

    def stop(self) -> None:
        self._stop_event.set()
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

    def _save_results(self) -> None:
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(self.output_dir, f"crack_result_{timestamp}.json")
            with self._lock:
                payload = {
                    "input_file": self.capture_file,
                    "tool": self._result.get("tool"),
                    "wordlist": self.wordlist,
                    "rules_file": self.rules_file,
                    "start_time": self._result.get("start_time"),
                    "end_time": self._result.get("end_time"),
                    "cracked": self._result.get("cracked", False),
                    "password": self._result.get("password"),
                    "status": self._result.get("status"),
                }
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            self.logger.info("Results saved to %s", filepath)
        except OSError as e:
            self.logger.error("Failed to save results: %s", e)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Password Crack - automated hashcat/aircrack-ng cracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-select tool, crack a captured handshake
  sudo python3 password_crack.py capture.pcap -w /usr/share/wordlists/rockyou.txt

  # Force hashcat with a rules file
  sudo python3 password_crack.py capture.22000 --tool hashcat --rules best64.rule

  # Force aircrack-ng, CPU only
  sudo python3 password_crack.py capture.cap -b AA:BB:CC:DD:EE:FF --tool aircrack --no-gpu

Note: Requires hashcat and/or aircrack-ng (plus hcxpcapngtool for conversion).
      For authorized security testing only.
        """,
    )

    parser.add_argument("capture_file", help="Capture file (.pcap/.cap/.22000/...)")
    parser.add_argument("-b", "--bssid", help="Target AP BSSID")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt",
                        help="Wordlist path (default: rockyou.txt)")
    parser.add_argument("--tool", default="auto", choices=["auto", "hashcat", "aircrack"],
                        help="Cracking tool to use (default: auto)")
    parser.add_argument("--rules", dest="rules_file", help="hashcat rules file")
    parser.add_argument("--no-gpu", dest="gpu", action="store_false",
                        help="Disable GPU acceleration (CPU only)")
    parser.add_argument("-t", "--timeout", type=int, default=3600,
                        help="Cracking timeout in seconds (default: 3600)")
    parser.add_argument("-o", "--output-dir", default="crack_results",
                        help="Output directory (default: crack_results)")
    parser.set_defaults(gpu=True)

    args = parser.parse_args()

    if args.bssid and not validate_mac(args.bssid):
        logger = setup_logging("password_crack")
        logger.error("Invalid BSSID format: %s", args.bssid)
        sys.exit(1)

    cracker = PasswordCracker(
        capture_file=args.capture_file,
        target_bssid=args.bssid,
        wordlist=args.wordlist,
        tool=args.tool,
        rules_file=args.rules_file,
        output_dir=args.output_dir,
        timeout=args.timeout,
        gpu=args.gpu,
    )

    tools = cracker.check_tools()
    if not tools["hashcat"] and not tools["aircrack"]:
        print("Neither hashcat nor aircrack-ng found. Install at least one.")
        sys.exit(1)

    result = cracker.start()

    print(f"\n{'='*60}")
    print("Password Crack Result")
    print(f"{'='*60}")
    print(f"Status:   {result.get('status')}")
    print(f"Tool:     {result.get('tool')}")
    if result.get("cracked"):
        print(f"Password: {result.get('password')}")

    sys.exit(0 if result.get("cracked") else 1)


if __name__ == "__main__":
    main()
