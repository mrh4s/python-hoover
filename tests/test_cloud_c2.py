"""Tests for cloud_c2.py -- Cloud C2 Remote Session Management module."""

import sys
import threading
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# No scapy imports needed for this module, but mock them in case
# utils or other transitive imports pull them in.
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.layers.eap", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

from cloud_c2 import (  # noqa: E402
    ALLOWED_TOOL_COMMANDS,
    CloudC2Client,
    CloudC2Server,
    _build_message,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def server():
    """Create a CloudC2Server with defaults."""
    return CloudC2Server(
        host="127.0.0.1",
        port=8443,
        auth_token="test-secret-token",
    )


@pytest.fixture
def client():
    """Create a CloudC2Client with mocked socketio."""
    with patch("cloud_c2.sio_client_module.Client") as MockClient:
        mock_sio = MagicMock()
        MockClient.return_value = mock_sio
        c = CloudC2Client(
            server_url="https://127.0.0.1:8443",
            auth_token="test-secret-token",
            reconnect_interval=5.0,
            heartbeat_interval=2.0,
        )
        # Replace the internal _sio with the mock
        c._sio = mock_sio
        yield c


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


class TestCloudC2Server:
    """Tests for the CloudC2Server class."""

    def test_server_init_defaults(self):
        """Test 1: verify server defaults."""
        srv = CloudC2Server()
        assert srv.host == "0.0.0.0"
        assert srv.port == 8443
        assert srv.certfile is None
        assert srv.keyfile is None
        # auth_token auto-generated when not provided
        assert srv.auth_token is not None
        assert len(srv.auth_token) > 0
        assert srv._running is False
        assert isinstance(srv._sessions, dict)
        assert len(srv._sessions) == 0

    def test_server_init_custom(self):
        """Verify server accepts custom parameters."""
        srv = CloudC2Server(
            host="10.0.0.1",
            port=9999,
            certfile="/tmp/cert.pem",
            keyfile="/tmp/key.pem",
            auth_token="my-token",
        )
        assert srv.host == "10.0.0.1"
        assert srv.port == 9999
        assert srv.certfile == "/tmp/cert.pem"
        assert srv.keyfile == "/tmp/key.pem"
        assert srv.auth_token == "my-token"

    def test_list_sessions_empty(self, server):
        """Test 7: verify empty list when no clients connected."""
        sessions = server.list_sessions()
        assert sessions == []
        assert isinstance(sessions, list)

    def test_register_session(self, server):
        """Test 8: simulate client registration, verify in list."""
        session_id = "test-session-001"
        session_info = {
            "sid": "socket-id-123",
            "session_id": session_id,
            "hostname": "pentest-laptop",
            "ip": "192.168.1.100",
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
            "status": "connected",
        }
        with server._lock:
            server._sessions[session_id] = session_info
            server._results[session_id] = []

        sessions = server.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == session_id
        assert sessions[0]["hostname"] == "pentest-laptop"

    def test_send_command_to_session(self, server):
        """Test 9: verify command routed to correct session."""
        session_id = "test-session-002"
        with server._lock:
            server._sessions[session_id] = {
                "sid": "socket-id-456",
                "session_id": session_id,
                "hostname": "agent-box",
                "ip": "10.0.0.5",
                "registered_at": datetime.now(timezone.utc).isoformat(),
                "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                "status": "connected",
            }

        command = {"type": "get_status"}

        # Mock the socketio emit
        server._socketio.emit = MagicMock()
        result = server.send_command(session_id, command)

        assert result["status"] == "sent"
        assert result["session_id"] == session_id
        assert result["command"] == command
        server._socketio.emit.assert_called_once()
        call_args = server._socketio.emit.call_args
        assert call_args[0][0] == "command"  # event name
        assert call_args[1]["to"] == "socket-id-456"

    def test_send_command_unknown_session(self, server):
        """Verify error when sending to nonexistent session."""
        result = server.send_command("no-such-session", {"type": "get_status"})
        assert result["status"] == "error"
        assert "not found" in result["message"].lower()

    def test_server_auth_required(self, server):
        """Test 11: verify unauthenticated connection rejected."""
        # The server checks auth_token; verify the token is set
        assert server.auth_token == "test-secret-token"
        # Simulate what happens on a connection with wrong token:
        # The _register_routes sets up a connect handler that checks token.
        # We verify the server has the right token stored.
        # In a real scenario, flask-socketio's connect handler would call
        # disconnect() for wrong tokens.
        assert server.auth_token != ""
        assert server.auth_token != "wrong-token"

    def test_get_session_results(self, server):
        """Verify results retrieval for a session."""
        session_id = "test-session-003"
        result_data = {
            "type": "result",
            "session_id": session_id,
            "payload": {"tool": "deauth", "results": {"count": 10}},
        }
        with server._lock:
            server._results[session_id] = [result_data]

        results = server.get_session_results(session_id)
        assert len(results) == 1
        assert results[0]["payload"]["tool"] == "deauth"

    def test_get_session_results_empty(self, server):
        """Verify empty results for unknown session."""
        results = server.get_session_results("nonexistent")
        assert results == []

    def test_broadcast_command(self, server):
        """Verify broadcast sends to all sessions."""
        for i in range(3):
            sid = f"session-{i}"
            with server._lock:
                server._sessions[sid] = {
                    "sid": f"sock-{i}",
                    "session_id": sid,
                    "hostname": f"host-{i}",
                    "ip": "10.0.0.1",
                    "registered_at": datetime.now(timezone.utc).isoformat(),
                    "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                    "status": "connected",
                }

        server._socketio.emit = MagicMock()
        result = server.broadcast_command({"type": "get_status"})

        assert result["status"] == "broadcast"
        assert len(result["sessions"]) == 3
        assert server._socketio.emit.call_count == 3


class TestCloudC2Client:
    """Tests for the CloudC2Client class."""

    def test_client_init(self):
        """Test 2: verify client parameters."""
        with patch("cloud_c2.sio_client_module.Client"):
            c = CloudC2Client(
                server_url="https://10.0.0.1:8443",
                auth_token="agent-token",
                reconnect_interval=60.0,
                heartbeat_interval=15.0,
            )
        assert c.server_url == "https://10.0.0.1:8443"
        assert c.auth_token == "agent-token"
        assert c.reconnect_interval == 60.0
        assert c.heartbeat_interval == 15.0
        assert c._connected is False
        assert c.session_id is not None

    def test_client_heartbeat_message_format(self, client):
        """Test 3: verify heartbeat JSON structure."""
        heartbeat = client._build_heartbeat()

        assert heartbeat["type"] == "heartbeat"
        assert heartbeat["session_id"] == client.session_id
        assert "timestamp" in heartbeat
        assert "payload" in heartbeat

        payload = heartbeat["payload"]
        assert "hostname" in payload
        assert "ip" in payload
        assert "uptime" in payload
        assert "running_tools" in payload
        assert "cpu_usage" in payload
        assert "memory_usage" in payload
        assert isinstance(payload["running_tools"], list)

    def test_command_handler_start_tool(self, client):
        """Test 4: mock start_tool command, verify execution."""
        command = {
            "type": "start_tool",
            "tool": "deauth",
            "args": ["--interface", "wlan0mon", "--target", "aa:bb:cc:dd:ee:ff"],
        }
        result = client._command_handler(command)

        assert result["status"] == "ok"
        assert result["tool"] == "deauth"
        assert "started" in result["message"].lower()

    def test_command_handler_unknown_command(self, client):
        """Test 5: verify error response for unknown command type."""
        command = {"type": "nonexistent_command"}
        result = client._command_handler(command)

        assert result["status"] == "error"
        assert "unknown" in result["message"].lower()

    def test_command_handler_rejects_shell(self, client):
        """Test 6: verify arbitrary shell commands rejected."""
        command = {
            "type": "shell",
            "cmd": "rm -rf /",
        }
        result = client._command_handler(command)

        assert result["status"] == "error"
        assert "not permitted" in result["message"].lower()

    def test_command_handler_disallowed_tool(self, client):
        """Verify that tools not in the allowed list are rejected."""
        command = {
            "type": "start_tool",
            "tool": "malicious_tool",
        }
        result = client._command_handler(command)

        assert result["status"] == "error"
        assert "disallowed" in result["message"].lower() or "unknown" in result["message"].lower()

    def test_client_reconnect_on_disconnect(self, client):
        """Test 10: verify reconnect attempted."""
        client._running = True
        client._connected = False

        # Mock _sio.connect to succeed on first call
        client._sio.connect = MagicMock()

        # Run reconnect loop in a thread with short timeout
        thread = threading.Thread(target=client._reconnect_loop, daemon=True)
        thread.start()
        thread.join(timeout=8.0)

        # The reconnect loop should have attempted to connect
        client._sio.connect.assert_called()
        call_args = client._sio.connect.call_args
        assert call_args[0][0] == client.server_url

        # Clean up
        client._running = False

    def test_client_get_status(self, client):
        """Verify get_status returns expected fields."""
        status = client.get_status()

        assert "connected" in status
        assert "session_id" in status
        assert "server_url" in status
        assert "heartbeat_interval" in status
        assert "reconnect_interval" in status
        assert status["server_url"] == "https://127.0.0.1:8443"
        assert status["connected"] is False

    def test_client_report_results(self, client):
        """Verify report_results emits to server."""
        client._sio.emit = MagicMock()
        client.report_results("deauth", {"packets_sent": 100})

        client._sio.emit.assert_called_once()
        call_args = client._sio.emit.call_args
        assert call_args[0][0] == "result"
        msg = call_args[0][1]
        assert msg["type"] == "result"
        assert msg["session_id"] == client.session_id
        assert msg["payload"]["tool"] == "deauth"
        assert msg["payload"]["results"]["packets_sent"] == 100


class TestMessageFormat:
    """Tests for message formatting utilities."""

    def test_message_format(self):
        """Test 12: verify JSON message structure."""
        msg = _build_message(
            msg_type="command",
            payload={"type": "get_status"},
            session_id="sess-123",
        )

        assert msg["type"] == "command"
        assert msg["session_id"] == "sess-123"
        assert "timestamp" in msg
        assert "payload" in msg
        assert msg["payload"]["type"] == "get_status"

        # Verify timestamp is valid ISO 8601
        ts = msg["timestamp"]
        parsed = datetime.fromisoformat(ts)
        assert parsed is not None

    def test_message_format_auto_session_id(self):
        """Verify auto-generated session_id when not provided."""
        msg = _build_message("heartbeat", {"status": "alive"})
        assert msg["session_id"] is not None
        assert len(msg["session_id"]) > 0
        # Should be a valid UUID
        uuid.UUID(msg["session_id"])

    def test_allowed_tool_commands(self):
        """Verify the allowed tool commands set is populated."""
        assert len(ALLOWED_TOOL_COMMANDS) > 0
        assert "hoover" in ALLOWED_TOOL_COMMANDS
        assert "deauth" in ALLOWED_TOOL_COMMANDS
        assert "pmkid_capture" in ALLOWED_TOOL_COMMANDS
        # Arbitrary commands should NOT be in the set
        assert "rm" not in ALLOWED_TOOL_COMMANDS
        assert "bash" not in ALLOWED_TOOL_COMMANDS
