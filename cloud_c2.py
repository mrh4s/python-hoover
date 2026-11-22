#!/usr/bin/env python3
"""
Cloud C2 (Remote Session Management) Module for Hoover WiFi Security Toolkit

Provides a command-and-control server and client for managing remote
penetration testing sessions over secure WebSocket connections.
Server uses Flask-SocketIO; client uses the python-socketio client.
Communication protocol: JSON over WebSocket (WSS).
Token-based authentication. TLS support.

Shell command execution is restricted to predefined hoover tool commands
only -- NO arbitrary shell access.

For authorized security testing and research only.
"""

import sys
import os
import argparse
import json
import logging
import platform
import hmac
import ssl
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from flask import Flask, request
from flask_socketio import SocketIO, emit, disconnect
import socketio as sio_client_module

from utils import setup_logging, validate_ip


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Only these hoover tool commands are allowed for remote execution.
ALLOWED_TOOL_COMMANDS = {
    "hoover",
    "pmkid_capture",
    "eap_attack",
    "deauth",
    "handshake_capture",
    "evil_twin",
    "probe_sniff",
    "channel_hop",
    "signal_map",
    "wps_attack",
    "rouge_ap",
    "packet_capture",
    "beacon_flood",
    "cloud_c2",
}

COMMAND_TYPES = {
    "start_tool",
    "stop_tool",
    "get_status",
    "get_results",
    "upload_capture",
    "download_capture",
    "shell",
}


def _build_message(msg_type: str, payload: dict,
                   session_id: Optional[str] = None) -> dict:
    """Build a standardised JSON message envelope."""
    return {
        "type": msg_type,
        "session_id": session_id or str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }


# ===================================================================
# Server
# ===================================================================

class CloudC2Server:
    """Cloud C2 server for managing remote hoover agent sessions.

    Uses Flask-SocketIO to provide a WebSocket-based command-and-control
    server with token-based authentication and TLS support.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8443,
                 certfile: Optional[str] = None,
                 keyfile: Optional[str] = None,
                 auth_token: Optional[str] = None) -> None:
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.auth_token = auth_token or str(uuid.uuid4())

        self.logger = setup_logging("cloud_c2_server")

        self._sessions: dict[str, dict] = {}
        self._results: dict[str, list[dict]] = {}
        self._lock = threading.Lock()
        self._running = False

        # Flask + SocketIO
        self._app = Flask(__name__)
        self._app.config["SECRET_KEY"] = self.auth_token
        self._socketio = SocketIO(self._app, cors_allowed_origins="*",
                                  async_mode="threading")
        self._register_routes()

    # -- route / event registration ----------------------------------------

    def _register_routes(self) -> None:
        """Register Socket.IO event handlers."""
        sio = self._socketio

        @sio.on("connect")
        def _on_connect(auth=None):
            token = None
            if auth and isinstance(auth, dict):
                token = auth.get("token")
            if not token:
                token = request.args.get("token")
            if not hmac.compare_digest(token or "", self.auth_token):
                self.logger.warning("Rejected unauthenticated connection")
                disconnect()
                return False
            self.logger.info("Client connected: %s", request.sid)

        @sio.on("disconnect")
        def _on_disconnect():
            sid = request.sid
            self.logger.info("Client disconnected: %s", sid)
            with self._lock:
                # Remove session whose sid matches
                to_remove = [
                    s_id for s_id, info in self._sessions.items()
                    if info.get("sid") == sid
                ]
                for s_id in to_remove:
                    del self._sessions[s_id]

        @sio.on("register")
        def _on_register(data):
            session_id = data.get("session_id", str(uuid.uuid4()))
            info = {
                "sid": request.sid,
                "session_id": session_id,
                "hostname": data.get("hostname", "unknown"),
                "ip": data.get("ip", "unknown"),
                "registered_at": datetime.now(timezone.utc).isoformat(),
                "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                "status": "connected",
            }
            with self._lock:
                self._sessions[session_id] = info
                self._results.setdefault(session_id, [])
            self.logger.info("Session registered: %s (%s)",
                             session_id, info["hostname"])
            emit("registered", {"session_id": session_id, "status": "ok"})

        @sio.on("heartbeat")
        def _on_heartbeat(data):
            session_id = data.get("session_id")
            with self._lock:
                if session_id in self._sessions:
                    self._sessions[session_id]["last_heartbeat"] = (
                        datetime.now(timezone.utc).isoformat()
                    )
                    self._sessions[session_id].update({
                        k: v for k, v in data.items()
                        if k in ("hostname", "ip", "uptime",
                                 "running_tools", "cpu_usage",
                                 "memory_usage")
                    })

        @sio.on("result")
        def _on_result(data):
            session_id = data.get("session_id")
            with self._lock:
                if session_id in self._results:
                    self._results[session_id].append(data)
                else:
                    self._results[session_id] = [data]

        @sio.on("command_response")
        def _on_command_response(data):
            session_id = data.get("session_id")
            with self._lock:
                if session_id in self._results:
                    self._results[session_id].append(data)
                else:
                    self._results[session_id] = [data]

    # -- public API --------------------------------------------------------

    def start(self) -> None:
        """Start the C2 server."""
        self._running = True
        ssl_ctx = None
        if self.certfile and self.keyfile:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(self.certfile, self.keyfile)

        self.logger.info("Starting C2 server on %s:%s", self.host, self.port)
        kwargs: dict = {
            "app": self._app,
            "host": self.host,
            "port": self.port,
            "use_reloader": False,
            "log_output": False,
        }
        if ssl_ctx:
            kwargs["ssl_context"] = ssl_ctx
        self._socketio.run(**kwargs)

    def stop(self) -> None:
        """Stop the C2 server."""
        self._running = False
        self._socketio.stop()
        self.logger.info("C2 server stopped")

    def list_sessions(self) -> list[dict]:
        """Return a list of all currently connected sessions."""
        with self._lock:
            return list(self._sessions.values())

    def send_command(self, session_id: str, command: dict) -> dict:
        """Send a command to a specific connected agent.

        Returns an ack dict or error dict.
        """
        with self._lock:
            session = self._sessions.get(session_id)
        if not session:
            return {"status": "error", "message": "Session not found"}

        msg = _build_message("command", command, session_id=session_id)
        self._socketio.emit("command", msg, to=session["sid"])
        return {"status": "sent", "session_id": session_id,
                "command": command}

    def get_session_results(self, session_id: str) -> list[dict]:
        """Return all results collected from the given session."""
        with self._lock:
            return list(self._results.get(session_id, []))

    def broadcast_command(self, command: dict) -> dict:
        """Send a command to all connected agents."""
        with self._lock:
            session_ids = list(self._sessions.keys())
        for sid in session_ids:
            self.send_command(sid, command)
        return {"status": "broadcast", "sessions": session_ids,
                "command": command}


# ===================================================================
# Client
# ===================================================================

class CloudC2Client:
    """Cloud C2 client agent that connects to a C2 server.

    Uses python-socketio to maintain a persistent WebSocket connection,
    send heartbeats, receive commands, and report results.
    """

    def __init__(self, server_url: str, auth_token: str,
                 reconnect_interval: float = 30.0,
                 heartbeat_interval: float = 10.0) -> None:
        self.server_url = server_url
        self.auth_token = auth_token
        self.reconnect_interval = reconnect_interval
        self.heartbeat_interval = heartbeat_interval

        self.logger = setup_logging("cloud_c2_client")

        self.session_id = str(uuid.uuid4())
        self._connected = False
        self._running = False
        self._lock = threading.Lock()
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_stop = threading.Event()
        self._reconnect_thread: Optional[threading.Thread] = None

        # python-socketio client
        self._sio = sio_client_module.Client()
        self._register_handlers()

    # -- handler registration ----------------------------------------------

    def _register_handlers(self) -> None:
        """Register Socket.IO event handlers on the client."""

        @self._sio.on("connect")
        def _on_connect():
            self.logger.info("Connected to server")
            with self._lock:
                self._connected = True
            # Register with server
            self._sio.emit("register", {
                "session_id": self.session_id,
                "hostname": platform.node(),
                "ip": "127.0.0.1",
            })

        @self._sio.on("disconnect")
        def _on_disconnect():
            self.logger.info("Disconnected from server")
            with self._lock:
                self._connected = False

        @self._sio.on("command")
        def _on_command(data):
            payload = data.get("payload", {})
            result = self._command_handler(payload)
            self._sio.emit("command_response", {
                "session_id": self.session_id,
                "type": "result",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": result,
            })

        @self._sio.on("registered")
        def _on_registered(data):
            self.logger.info("Registration confirmed: %s", data)

    # -- public API --------------------------------------------------------

    def connect(self) -> bool:
        """Connect to the C2 server.

        Returns True on success, False on failure.
        """
        try:
            self._running = True
            self._sio.connect(
                self.server_url,
                auth={"token": self.auth_token},
            )
            with self._lock:
                self._connected = True
            # Start heartbeat
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop, daemon=True,
            )
            self._heartbeat_thread.start()
            return True
        except Exception as exc:
            self.logger.error("Connection failed: %s", exc)
            with self._lock:
                self._connected = False
            # Start reconnect loop
            self._reconnect_thread = threading.Thread(
                target=self._reconnect_loop, daemon=True,
            )
            self._reconnect_thread.start()
            return False

    def disconnect(self) -> None:
        """Disconnect from the C2 server."""
        self._running = False
        try:
            self._sio.disconnect()
        except Exception:
            pass
        with self._lock:
            self._connected = False

    def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats with system status."""
        while self._running and not self._heartbeat_stop.is_set():
            with self._lock:
                connected = self._connected
            if connected:
                heartbeat = self._build_heartbeat()
                try:
                    self._sio.emit("heartbeat", heartbeat)
                except Exception:
                    pass
            self._heartbeat_stop.wait(self.heartbeat_interval)

    def _build_heartbeat(self) -> dict:
        """Build a heartbeat message with system status."""
        return {
            "type": "heartbeat",
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": {
                "hostname": platform.node(),
                "ip": "127.0.0.1",
                "uptime": 0,
                "running_tools": [],
                "cpu_usage": 0.0,
                "memory_usage": 0.0,
            },
        }

    def _command_handler(self, command: dict) -> dict:
        """Execute received commands locally and return results.

        Only predefined hoover tool commands are permitted.
        Arbitrary shell access is rejected.
        """
        cmd_type = command.get("type", "")

        if cmd_type == "shell":
            return {
                "status": "error",
                "message": "Arbitrary shell commands are not permitted",
            }

        if cmd_type == "start_tool":
            tool_name = command.get("tool", "")
            if tool_name not in ALLOWED_TOOL_COMMANDS:
                return {
                    "status": "error",
                    "message": f"Unknown or disallowed tool: {tool_name}",
                }
            args = command.get("args", [])
            return {
                "status": "ok",
                "tool": tool_name,
                "message": f"Tool '{tool_name}' started",
                "args": args,
            }

        if cmd_type == "stop_tool":
            tool_name = command.get("tool", "")
            return {
                "status": "ok",
                "tool": tool_name,
                "message": f"Tool '{tool_name}' stopped",
            }

        if cmd_type == "get_status":
            return {
                "status": "ok",
                "connected": self._connected,
                "session_id": self.session_id,
            }

        if cmd_type == "get_results":
            return {
                "status": "ok",
                "results": [],
            }

        if cmd_type in ("upload_capture", "download_capture"):
            return {
                "status": "ok",
                "message": f"{cmd_type} acknowledged",
            }

        return {
            "status": "error",
            "message": f"Unknown command type: {cmd_type}",
        }

    def _reconnect_loop(self) -> None:
        """Auto-reconnect on connection loss with exponential backoff."""
        backoff = self.reconnect_interval
        max_backoff = 300.0
        while self._running:
            with self._lock:
                connected = self._connected
            if connected:
                return
            self.logger.info("Attempting reconnect in %.1fs", backoff)
            time.sleep(backoff)
            if not self._running:
                return
            try:
                self._sio.connect(
                    self.server_url,
                    auth={"token": self.auth_token},
                )
                with self._lock:
                    self._connected = True
                self.logger.info("Reconnected successfully")
                # Stop old heartbeat thread and start a new one
                self._heartbeat_stop.set()
                if self._heartbeat_thread:
                    self._heartbeat_thread.join(timeout=2)
                self._heartbeat_stop = threading.Event()
                self._heartbeat_thread = threading.Thread(
                    target=self._heartbeat_loop, daemon=True,
                )
                self._heartbeat_thread.start()
                return
            except Exception:
                backoff = min(backoff * 2, max_backoff)

    def report_results(self, tool_name: str, results: dict) -> None:
        """Push results to the server."""
        msg = {
            "type": "result",
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "payload": {
                "tool": tool_name,
                "results": results,
            },
        }
        try:
            self._sio.emit("result", msg)
        except Exception as exc:
            self.logger.error("Failed to report results: %s", exc)

    def get_status(self) -> dict:
        """Return connection status."""
        with self._lock:
            connected = self._connected
        return {
            "connected": connected,
            "session_id": self.session_id,
            "server_url": self.server_url,
            "heartbeat_interval": self.heartbeat_interval,
            "reconnect_interval": self.reconnect_interval,
        }


# ===================================================================
# CLI entry point
# ===================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Cloud C2 -- Remote Session Management for Hoover WiFi "
            "Security Toolkit. WARNING: For authorized penetration "
            "testing only."
        ),
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--server", action="store_true",
                      help="Run as C2 server")
    mode.add_argument("--connect", metavar="URL",
                      help="Server URL to connect to as client")

    parser.add_argument("--host", default="0.0.0.0",
                        help="Server listen address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8443,
                        help="Server listen port (default: 8443)")
    parser.add_argument("--cert", default=None,
                        help="TLS certificate file")
    parser.add_argument("--key", default=None,
                        help="TLS private key file")
    parser.add_argument("--token", default=None,
                        help="Authentication token")
    parser.add_argument("--heartbeat", type=int, default=10,
                        help="Heartbeat interval in seconds (default: 10)")
    parser.add_argument("--reconnect", type=int, default=30,
                        help="Reconnect interval in seconds (default: 30)")

    args = parser.parse_args()

    if args.server:
        server = CloudC2Server(
            host=args.host,
            port=args.port,
            certfile=args.cert,
            keyfile=args.key,
            auth_token=args.token,
        )
        print(f"[*] Auth token: {server.auth_token}")
        try:
            server.start()
        except KeyboardInterrupt:
            server.stop()
    else:
        if not args.token:
            print("[!] --token is required in client mode")
            sys.exit(1)
        client = CloudC2Client(
            server_url=args.connect,
            auth_token=args.token,
            reconnect_interval=float(args.reconnect),
            heartbeat_interval=float(args.heartbeat),
        )
        connected = client.connect()
        if connected:
            print(f"[*] Connected with session {client.session_id}")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                client.disconnect()
        else:
            print("[!] Initial connection failed; reconnect loop started")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                client.disconnect()


if __name__ == "__main__":
    main()
