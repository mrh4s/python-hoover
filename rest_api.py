#!/usr/bin/env python3
"""
Hoover REST API - Programmatic JSON API for the Hoover WiFi Security Toolkit.

Exposes a token-authenticated, rate-limited REST API that wraps the
toolkit's scanning and attack modules so they can be driven
programmatically (e.g. from automation, CI, or a remote dashboard),
separately from the HTML GUI in hoover_web.py.

*** AUTHORIZED PENTESTING USE ONLY ***
This API can start active wireless attacks (deauthentication, rogue APs,
credential-harvesting MITM, etc.). Only run it against networks and
clients you own or have explicit written authorization to test. Running
this API open on an untrusted network is dangerous -- always use a
strong auth token (the default) and bind to 127.0.0.1 unless you have a
specific, authorized reason to expose it more broadly.
"""

import argparse
import hmac
import importlib
import os
import secrets
import sys
import threading
import time
import uuid
from functools import wraps
from pathlib import Path
from typing import Callable, Optional

from flask import Blueprint, Flask, jsonify, request, send_from_directory
from werkzeug.serving import make_server

from utils import setup_logging

CAPTURES_DIR = Path("captures")
REPORTS_DIR = Path("reports")

# Rate limit: requests allowed per IP within the rolling window below.
RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW = 60.0

# Tool name -> (module name, class name). Imported lazily (inside
# get_tool_class) so that importing rest_api itself never pulls in scapy
# or any hardware-touching module -- those are only needed once a tool is
# actually started.
TOOL_REGISTRY: dict = {
    "ap_scanner": ("ap_scanner", "APScanner"),
    "handshake": ("handshake_capture", "HandshakeCapture"),
    "deauth": ("deauth", "DeauthAttacker"),
    "karma": ("karma_attack", "KarmaAttack"),
    "pmkid": ("pmkid_capture", "PMKIDCapture"),
    "eap": ("eap_attack", "EAPAttack"),
    "mitm": ("mitm_attack", "MitMAttack"),
    "wps": ("wps_attack", "WPSAttack"),
    "packet_replay": ("packet_replay", "PacketReplay"),
    "network_mapper": ("network_mapper", "NetworkMapper"),
    "ble_scanner": ("ble_scanner", "BLEScanner"),
    "wids": ("wids", "WIDSMonitor"),
    "captive_portal": ("captive_portal", "CaptivePortal"),
}

# Maps the generic "attack type" path segment used by /api/v1/attack/{type}
# onto the same tool registry entries.
ATTACK_TYPES = {
    "deauth": "deauth",
    "karma": "karma",
    "pmkid": "pmkid",
    "eap": "eap",
    "mitm": "mitm",
    "wps": "wps",
}


def get_tool_class(name: str):
    """Lazily import and return the tool class registered under ``name``.

    Returns None if ``name`` is not a known tool. Import errors (e.g. a
    missing optional system dependency) propagate to the caller.
    """
    entry = TOOL_REGISTRY.get(name)
    if entry is None:
        return None
    module_name, class_name = entry
    module = importlib.import_module(module_name)
    return getattr(module, class_name)


class APIError(Exception):
    """Base class for API errors that carry a stable machine-readable code."""

    code = "ERROR"


class AuthError(APIError):
    code = "UNAUTHORIZED"


class NotFoundError(APIError):
    code = "NOT_FOUND"


class BadRequestError(APIError):
    code = "BAD_REQUEST"


class RateLimitError(APIError):
    code = "RATE_LIMITED"


_STATUS_TO_CODE = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    429: "RATE_LIMITED",
    500: "INTERNAL_ERROR",
}


class HooverAPI:
    """Flask-based REST API wrapping the Hoover toolkit's tool classes."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        auth_token: Optional[str] = None,
        enable_cors: bool = False,
    ) -> None:
        self.host: str = host
        self.port: int = port
        self.auth_token: str = auth_token or self._generate_token()
        self.enable_cors: bool = enable_cors
        self.cors_origins: list = ["*"]
        # Set to False by the CLI's --no-auth flag. Authentication is
        # enabled by default regardless of whether a token was supplied.
        self.require_auth: bool = True

        self.logger = setup_logging("rest_api")

        self._active_tools: dict = {}
        self._lock = threading.Lock()
        self._rate_limits: dict = {}
        self._rate_lock = threading.Lock()
        self._server = None
        self._server_thread: Optional[threading.Thread] = None

        self.app = Flask(__name__)
        self.blueprint = Blueprint("hoover_api", __name__, url_prefix="/api/v1")
        self._register_routes()
        self.app.register_blueprint(self.blueprint)

        if self.enable_cors:
            self.app.after_request(self._apply_cors_headers)

    # -- Auth / rate limiting ------------------------------------------------

    def _generate_token(self) -> str:
        """Generate a random API token for authentication."""
        return secrets.token_hex(32)

    def _check_rate_limit(self, identity: str) -> bool:
        """Return True if ``identity`` (typically an IP) is over the limit."""
        now = time.time()
        cutoff = now - RATE_LIMIT_WINDOW
        with self._rate_lock:
            timestamps = self._rate_limits.setdefault(identity, [])
            timestamps[:] = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= RATE_LIMIT_REQUESTS:
                return True
            timestamps.append(now)
            return False

    def _require_auth(self, f: Callable) -> Callable:
        """Decorator: verify the Bearer token and enforce rate limiting."""

        @wraps(f)
        def decorated(*args, **kwargs):
            identity = request.remote_addr or "unknown"
            if self._check_rate_limit(identity):
                return self._handle_error(
                    RateLimitError("Rate limit exceeded (60 requests/minute)"), 429
                )

            if self.require_auth:
                header = request.headers.get("Authorization", "")
                if not header.startswith("Bearer "):
                    return self._handle_error(
                        AuthError("Missing or malformed Authorization header"), 401
                    )
                token = header[len("Bearer ") :].strip()
                if not token or not hmac.compare_digest(token, self.auth_token):
                    return self._handle_error(AuthError("Invalid API token"), 401)

            return f(*args, **kwargs)

        return decorated

    def _apply_cors_headers(self, response):
        origin = request.headers.get("Origin")
        allowed = "*"
        if self.cors_origins and self.cors_origins != ["*"]:
            allowed = origin if origin in self.cors_origins else self.cors_origins[0]
        response.headers["Access-Control-Allow-Origin"] = allowed
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        return response

    # -- Error handling -------------------------------------------------------

    def _handle_error(self, error: Exception, status: int) -> tuple:
        """Standard JSON error response format."""
        code = getattr(error, "code", None) or _STATUS_TO_CODE.get(status, "ERROR")
        self.logger.error("API error [%s]: %s", code, error)
        return jsonify({"success": False, "error": str(error), "code": code}), status

    # -- Tool lifecycle helpers ------------------------------------------------

    def _start_tool(self, tool_name: str, params: dict) -> str:
        """Instantiate ``tool_name`` with ``params`` and start it in a
        background daemon thread. Returns a task_id (UUID string)."""
        cls = get_tool_class(tool_name)
        if cls is None:
            raise NotFoundError(f"Unknown tool: {tool_name}")

        try:
            instance = cls(**params)
        except TypeError as exc:
            raise BadRequestError(f"Invalid parameters for '{tool_name}': {exc}") from exc

        task_id = str(uuid.uuid4())

        def _runner():
            try:
                if hasattr(instance, "start"):
                    instance.start()
                with self._lock:
                    entry = self._active_tools.get(tool_name)
                    if entry is not None and entry["task_id"] == task_id:
                        entry["status"] = "completed"
            except Exception as exc:  # pragma: no cover - defensive
                self.logger.error("Tool '%s' raised during run: %s", tool_name, exc)
                with self._lock:
                    entry = self._active_tools.get(tool_name)
                    if entry is not None and entry["task_id"] == task_id:
                        entry["status"] = "error"
                        entry["error"] = str(exc)

        thread = threading.Thread(target=_runner, daemon=True)
        with self._lock:
            self._active_tools[tool_name] = {
                "task_id": task_id,
                "tool": tool_name,
                "instance": instance,
                "thread": thread,
                "status": "running",
                "started_at": time.time(),
                "params": params,
                "error": None,
            }
        thread.start()
        return task_id

    def _discover_interfaces(self) -> list:
        """Best-effort discovery of wireless-capable network interfaces."""
        net_dir = Path("/sys/class/net")
        try:
            if not net_dir.exists():
                return []
            found = []
            for entry in sorted(net_dir.iterdir()):
                if (entry / "wireless").exists() or (entry / "phy80211").exists():
                    found.append(entry.name)
            return found
        except OSError:
            return []

    def _list_output_files(self, directory: Path) -> list:
        if not directory.exists():
            return []
        files = []
        for p in sorted(directory.iterdir()):
            if p.is_file():
                try:
                    stat = p.stat()
                    files.append(
                        {
                            "filename": p.name,
                            "size": stat.st_size,
                            "modified": stat.st_mtime,
                        }
                    )
                except OSError:
                    continue
        return files

    # -- Routes ---------------------------------------------------------------

    def _register_routes(self) -> None:
        """Register all API endpoint routes."""
        bp = self.blueprint

        @bp.route("/status", methods=["GET"])
        @self._require_auth
        def api_status():
            with self._lock:
                running = [n for n, e in self._active_tools.items() if e["status"] == "running"]
            data = {
                "service": "hoover-api",
                "version": "1.0.0",
                "auth_required": self.require_auth,
                "available_tools": sorted(TOOL_REGISTRY.keys()),
                "running_tools": running,
            }
            return jsonify({"success": True, "data": data})

        @bp.route("/interfaces", methods=["GET"])
        @self._require_auth
        def api_interfaces():
            return jsonify({"success": True, "data": self._discover_interfaces()})

        @bp.route("/tools", methods=["GET"])
        @self._require_auth
        def api_list_tools():
            with self._lock:
                active = {name: entry["status"] for name, entry in self._active_tools.items()}
            data = [
                {"name": name, "status": active.get(name, "idle")}
                for name in sorted(TOOL_REGISTRY.keys())
            ]
            return jsonify({"success": True, "data": data})

        @bp.route("/tools/<tool>/start", methods=["POST"])
        @self._require_auth
        def api_start_tool(tool):
            if tool not in TOOL_REGISTRY:
                return self._handle_error(NotFoundError(f"Unknown tool: {tool}"), 404)
            body = request.get_json(silent=True) or {}
            if "interface" not in body:
                return self._handle_error(
                    BadRequestError("Missing required parameter: interface"), 400
                )
            try:
                task_id = self._start_tool(tool, body)
            except BadRequestError as exc:
                return self._handle_error(exc, 400)
            except Exception as exc:
                return self._handle_error(exc, 500)
            return jsonify(
                {
                    "success": True,
                    "data": {"task_id": task_id, "tool": tool, "status": "running"},
                }
            ), 202

        @bp.route("/tools/<tool>/stop", methods=["POST"])
        @self._require_auth
        def api_stop_tool(tool):
            with self._lock:
                entry = self._active_tools.get(tool)
            if entry is None or entry["status"] != "running":
                return self._handle_error(NotFoundError(f"Tool '{tool}' is not running"), 404)
            instance = entry["instance"]
            try:
                if hasattr(instance, "stop"):
                    instance.stop()
            except Exception as exc:
                return self._handle_error(exc, 500)
            with self._lock:
                entry["status"] = "stopped"
            return jsonify({"success": True, "data": {"tool": tool, "status": "stopped"}})

        @bp.route("/tools/<tool>/status", methods=["GET"])
        @self._require_auth
        def api_tool_status(tool):
            with self._lock:
                entry = self._active_tools.get(tool)
            if entry is None:
                return self._handle_error(NotFoundError(f"No task found for tool '{tool}'"), 404)
            instance = entry["instance"]
            data = {"tool": tool, "task_id": entry["task_id"], "status": entry["status"]}
            if entry.get("error"):
                data["error"] = entry["error"]
            if hasattr(instance, "get_status"):
                try:
                    data["details"] = instance.get_status()
                except Exception:
                    pass
            return jsonify({"success": True, "data": data})

        @bp.route("/captures", methods=["GET"])
        @self._require_auth
        def api_list_captures():
            return jsonify({"success": True, "data": self._list_output_files(CAPTURES_DIR)})

        @bp.route("/captures/<filename>", methods=["GET"])
        @self._require_auth
        def api_download_capture(filename):
            safe_name = os.path.basename(filename)
            if not safe_name or safe_name != filename:
                return self._handle_error(BadRequestError("Invalid filename"), 400)
            file_path = CAPTURES_DIR / safe_name
            if not file_path.is_file():
                return self._handle_error(NotFoundError(f"Capture not found: {safe_name}"), 404)
            return send_from_directory(str(CAPTURES_DIR.resolve()), safe_name, as_attachment=True)

        @bp.route("/results/<tool>", methods=["GET"])
        @self._require_auth
        def api_get_results(tool):
            with self._lock:
                entry = self._active_tools.get(tool)
            if entry is None:
                return self._handle_error(
                    NotFoundError(f"No results available for tool '{tool}'"), 404
                )
            instance = entry["instance"]
            results = {}
            for attr in ("get_results", "get_status", "get_stats"):
                if hasattr(instance, attr):
                    try:
                        results = getattr(instance, attr)()
                    except Exception:
                        results = {}
                    break
            return jsonify({"success": True, "data": results})

        @bp.route("/scan/ap", methods=["POST"])
        @self._require_auth
        def api_scan_ap():
            body = request.get_json(silent=True) or {}
            if "interface" not in body:
                return self._handle_error(
                    BadRequestError("Missing required parameter: interface"), 400
                )
            try:
                task_id = self._start_tool("ap_scanner", body)
            except BadRequestError as exc:
                return self._handle_error(exc, 400)
            except Exception as exc:
                return self._handle_error(exc, 500)
            with self._lock:
                entry = self._active_tools["ap_scanner"]
            timeout = body.get("timeout", 30)
            entry["thread"].join(timeout=timeout + 5)
            instance = entry["instance"]
            access_points = getattr(instance, "access_points", {})
            return jsonify(
                {
                    "success": True,
                    "data": {"task_id": task_id, "access_points": access_points},
                }
            )

        @bp.route("/scan/clients", methods=["POST"])
        @self._require_auth
        def api_scan_clients():
            body = request.get_json(silent=True) or {}
            if "interface" not in body:
                return self._handle_error(
                    BadRequestError("Missing required parameter: interface"), 400
                )
            try:
                task_id = self._start_tool("ap_scanner", body)
            except BadRequestError as exc:
                return self._handle_error(exc, 400)
            except Exception as exc:
                return self._handle_error(exc, 500)
            return jsonify(
                {"success": True, "data": {"task_id": task_id, "status": "running"}}
            ), 202

        @bp.route("/fingerprints", methods=["GET"])
        @self._require_auth
        def api_fingerprints():
            with self._lock:
                entry = self._active_tools.get("ap_scanner")
            fingerprints = {}
            if entry is not None:
                instance = entry["instance"]
                for attr in ("fingerprints", "clients"):
                    if hasattr(instance, attr):
                        fingerprints = getattr(instance, attr)
                        break
            return jsonify({"success": True, "data": fingerprints})

        @bp.route("/handshake/capture", methods=["POST"])
        @self._require_auth
        def api_handshake_capture():
            body = request.get_json(silent=True) or {}
            required = ("interface", "target_bssid")
            missing = [p for p in required if p not in body]
            if missing:
                return self._handle_error(
                    BadRequestError(f"Missing required parameter(s): {', '.join(missing)}"), 400
                )
            try:
                task_id = self._start_tool("handshake", body)
            except BadRequestError as exc:
                return self._handle_error(exc, 400)
            except Exception as exc:
                return self._handle_error(exc, 500)
            return jsonify(
                {
                    "success": True,
                    "data": {"task_id": task_id, "tool": "handshake", "status": "running"},
                }
            ), 202

        @bp.route("/handshake/verify", methods=["POST"])
        @self._require_auth
        def api_handshake_verify():
            body = request.get_json(silent=True) or {}
            filename = body.get("filename")
            if not filename:
                return self._handle_error(
                    BadRequestError("Missing required parameter: filename"), 400
                )
            safe_name = os.path.basename(filename)
            file_path = CAPTURES_DIR / safe_name
            if not file_path.is_file():
                return self._handle_error(NotFoundError(f"Capture not found: {safe_name}"), 404)
            valid = file_path.stat().st_size > 0
            return jsonify(
                {
                    "success": True,
                    "data": {"filename": safe_name, "valid": valid},
                }
            )

        @bp.route("/attack/<attack_type>", methods=["POST"])
        @self._require_auth
        def api_attack(attack_type):
            tool_name = ATTACK_TYPES.get(attack_type)
            if tool_name is None:
                return self._handle_error(NotFoundError(f"Unknown attack type: {attack_type}"), 404)
            body = request.get_json(silent=True) or {}
            if "interface" not in body:
                return self._handle_error(
                    BadRequestError("Missing required parameter: interface"), 400
                )
            try:
                task_id = self._start_tool(tool_name, body)
            except BadRequestError as exc:
                return self._handle_error(exc, 400)
            except Exception as exc:
                return self._handle_error(exc, 500)
            return jsonify(
                {
                    "success": True,
                    "data": {"task_id": task_id, "attack": attack_type, "status": "running"},
                }
            ), 202

        @bp.route("/reports", methods=["GET"])
        @self._require_auth
        def api_list_reports():
            return jsonify({"success": True, "data": self._list_output_files(REPORTS_DIR)})

        @bp.route("/reports/generate", methods=["POST"])
        @self._require_auth
        def api_generate_report():
            body = request.get_json(silent=True) or {}
            try:
                from reporting import ReportGenerator
            except ImportError as exc:
                return self._handle_error(APIError(f"Reporting module not available: {exc}"), 500)
            try:
                generator = ReportGenerator(**body.get("options", {}))
                for section in body.get("sections", []):
                    generator.add_section(
                        section.get("title", ""),
                        section.get("content", ""),
                        section.get("data"),
                    )
                report_path = generator.generate() if hasattr(generator, "generate") else None
            except Exception as exc:
                return self._handle_error(exc, 500)
            return jsonify({"success": True, "data": {"report": report_path}}), 201

    # -- Server lifecycle -------------------------------------------------------

    def start(self) -> None:
        """Start the Flask API server (blocking)."""
        self.logger.info("Starting Hoover REST API on %s:%s", self.host, self.port)
        if self.require_auth:
            self.logger.info("API token: %s", self.auth_token)
        else:
            self.logger.warning("Authentication is DISABLED -- do not expose this port")
        self._server = make_server(self.host, self.port, self.app)
        self._server_thread = threading.current_thread()
        self._server.serve_forever()

    def start_background(self) -> None:
        """Start the Flask API server in a background daemon thread."""
        self._server = make_server(self.host, self.port, self.app)
        self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._server_thread.start()

    def stop(self) -> None:
        """Stop the API server."""
        if self._server is not None:
            self._server.shutdown()
            self._server = None
        with self._lock:
            for entry in self._active_tools.values():
                instance = entry.get("instance")
                if (
                    entry.get("status") == "running"
                    and instance is not None
                    and hasattr(instance, "stop")
                ):
                    try:
                        instance.stop()
                    except Exception:
                        pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Hoover REST API - JSON API server for the Hoover WiFi Security Toolkit. "
            "FOR AUTHORIZED PENETRATION TESTING USE ONLY. This server can start active "
            "wireless attacks; only run it against networks and clients you own or have "
            "explicit written authorization to test."
        )
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument(
        "--token", default=None, help="Pre-set API token (otherwise auto-generated)"
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="DANGEROUS: disable authentication entirely",
    )
    parser.add_argument(
        "--cors-origins",
        default=None,
        help="Comma-separated list of allowed CORS origins (enables CORS)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = parser.parse_args()

    enable_cors = bool(args.cors_origins)
    api = HooverAPI(
        host=args.host,
        port=args.port,
        auth_token=args.token,
        enable_cors=enable_cors,
    )
    if enable_cors:
        api.cors_origins = [o.strip() for o in args.cors_origins.split(",") if o.strip()]
    if args.no_auth:
        api.require_auth = False
        print("WARNING: authentication is DISABLED. Do not expose this port.", file=sys.stderr)
    elif not args.token:
        print(f"API token (keep this secret): {api.auth_token}")

    try:
        api.start()
    except KeyboardInterrupt:
        api.stop()


if __name__ == "__main__":
    main()
