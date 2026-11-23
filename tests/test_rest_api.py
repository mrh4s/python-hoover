"""Tests for rest_api.py -- Hoover REST API."""

import sys
import time

import pytest

import rest_api  # noqa: E402
from rest_api import TOOL_REGISTRY, HooverAPI  # noqa: E402

TEST_TOKEN = "test-token-0123456789abcdef"


class _FakeTool:
    """A lightweight stand-in for a real tool class (APScanner, etc.)."""

    instances = []

    def __init__(self, interface, **kwargs):
        self.interface = interface
        self.kwargs = kwargs
        self.started = False
        self.stopped = False
        self.access_points = {"AA:BB:CC:DD:EE:FF": {"ssid": "TestNet"}}
        _FakeTool.instances.append(self)

    def start(self):
        time.sleep(0.1)
        self.started = True

    def stop(self):
        self.stopped = True

    def get_status(self) -> dict:
        return {"started": self.started, "stopped": self.stopped}


@pytest.fixture(autouse=True)
def _reset_fake_tool_instances():
    _FakeTool.instances = []
    yield
    _FakeTool.instances = []


@pytest.fixture
def api():
    return HooverAPI(host="127.0.0.1", port=8080, auth_token=TEST_TOKEN, enable_cors=False)


@pytest.fixture
def client(api):
    return api.app.test_client()


@pytest.fixture
def auth_headers():
    return {"Authorization": f"Bearer {TEST_TOKEN}"}


@pytest.fixture
def with_fake_tool(monkeypatch):
    """Register 'fake_tool' in the tool registry for start/stop/status tests."""
    monkeypatch.setitem(TOOL_REGISTRY, "fake_tool", ("tests.test_rest_api", "_FakeTool"))

    def _fake_get_tool_class(name):
        if name == "fake_tool":
            return _FakeTool
        return None

    monkeypatch.setattr(rest_api, "get_tool_class", _fake_get_tool_class)
    return "fake_tool"


# ---------------------------------------------------------------------------
# 1. Status endpoint
# ---------------------------------------------------------------------------

class TestStatusEndpoint:
    def test_api_status_endpoint(self, client, auth_headers):
        resp = client.get("/api/v1/status", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        assert "data" in body
        assert "available_tools" in body["data"]


# ---------------------------------------------------------------------------
# 2-4. Authentication
# ---------------------------------------------------------------------------

class TestAuthentication:
    def test_api_requires_auth(self, client):
        resp = client.get("/api/v1/status")
        assert resp.status_code == 401
        body = resp.get_json()
        assert body["success"] is False

    def test_api_valid_auth(self, client, auth_headers):
        resp = client.get("/api/v1/status", headers=auth_headers)
        assert resp.status_code == 200

    def test_api_invalid_auth(self, client):
        resp = client.get(
            "/api/v1/status", headers={"Authorization": "Bearer wrong-token"}
        )
        assert resp.status_code == 401
        body = resp.get_json()
        assert body["success"] is False
        assert body["code"] == "UNAUTHORIZED"


# ---------------------------------------------------------------------------
# 5-6. Interfaces / tools listing
# ---------------------------------------------------------------------------

class TestListingEndpoints:
    def test_api_list_interfaces(self, client, auth_headers):
        resp = client.get("/api/v1/interfaces", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        assert isinstance(body["data"], list)

    def test_api_list_tools(self, client, auth_headers):
        resp = client.get("/api/v1/tools", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        names = {entry["name"] for entry in body["data"]}
        assert set(TOOL_REGISTRY.keys()).issubset(names)


# ---------------------------------------------------------------------------
# 7-10. Tool start/stop/status lifecycle
# ---------------------------------------------------------------------------

class TestToolLifecycle:
    def test_api_start_tool(self, client, auth_headers, with_fake_tool):
        tool = with_fake_tool
        resp = client.post(
            f"/api/v1/tools/{tool}/start",
            json={"interface": "wlan0mon"},
            headers=auth_headers,
        )
        assert resp.status_code == 202
        body = resp.get_json()
        assert body["success"] is True
        assert "task_id" in body["data"]

    def test_api_start_tool_missing_params(self, client, auth_headers, with_fake_tool):
        tool = with_fake_tool
        resp = client.post(
            f"/api/v1/tools/{tool}/start", json={}, headers=auth_headers
        )
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["success"] is False
        assert body["code"] == "BAD_REQUEST"

    def test_api_stop_tool_not_running(self, client, auth_headers, with_fake_tool):
        tool = with_fake_tool
        resp = client.post(f"/api/v1/tools/{tool}/stop", headers=auth_headers)
        assert resp.status_code == 404
        body = resp.get_json()
        assert body["success"] is False

    def test_api_tool_status(self, client, auth_headers, with_fake_tool):
        tool = with_fake_tool
        start_resp = client.post(
            f"/api/v1/tools/{tool}/start",
            json={"interface": "wlan0mon"},
            headers=auth_headers,
        )
        assert start_resp.status_code == 202

        status_resp = client.get(f"/api/v1/tools/{tool}/status", headers=auth_headers)
        assert status_resp.status_code == 200
        body = status_resp.get_json()
        assert body["success"] is True
        assert body["data"]["status"] in ("running", "completed")
        assert body["data"]["tool"] == tool


# ---------------------------------------------------------------------------
# 11. Captures listing
# ---------------------------------------------------------------------------

class TestCapturesEndpoint:
    def test_api_list_captures(self, client, auth_headers, monkeypatch, tmp_path):
        captures_dir = tmp_path / "captures"
        captures_dir.mkdir()
        (captures_dir / "handshake.pcap").write_bytes(b"fake-pcap-data")
        monkeypatch.setattr(rest_api, "CAPTURES_DIR", captures_dir)

        resp = client.get("/api/v1/captures", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["success"] is True
        filenames = {entry["filename"] for entry in body["data"]}
        assert "handshake.pcap" in filenames


# ---------------------------------------------------------------------------
# 12. Error format
# ---------------------------------------------------------------------------

class TestErrorFormat:
    def test_api_error_format(self, client, auth_headers):
        resp = client.get("/api/v1/tools/does_not_exist/status", headers=auth_headers)
        assert resp.status_code == 404
        body = resp.get_json()
        assert body["success"] is False
        assert "error" in body
        assert "code" in body
        assert isinstance(body["error"], str)


# ---------------------------------------------------------------------------
# 13. CORS headers
# ---------------------------------------------------------------------------

class TestCORS:
    def test_api_cors_headers(self):
        cors_api = HooverAPI(
            host="127.0.0.1", port=8081, auth_token=TEST_TOKEN, enable_cors=True
        )
        cors_client = cors_api.app.test_client()
        resp = cors_client.get(
            "/api/v1/status",
            headers={"Authorization": f"Bearer {TEST_TOKEN}"},
        )
        assert resp.status_code == 200
        assert "Access-Control-Allow-Origin" in resp.headers


# ---------------------------------------------------------------------------
# 14. CLI argument parsing
# ---------------------------------------------------------------------------

class TestCLI:
    def test_cli_host_port(self, monkeypatch):
        captured = {}

        class _RecordingAPI(HooverAPI):
            def __init__(self, *args, **kwargs):
                captured["host"] = kwargs.get("host")
                captured["port"] = kwargs.get("port")
                super().__init__(*args, **kwargs)

            def start(self):
                # Don't actually bind a socket during tests.
                pass

        monkeypatch.setattr(rest_api, "HooverAPI", _RecordingAPI)
        monkeypatch.setattr(
            sys, "argv", ["rest_api.py", "--host", "0.0.0.0", "--port", "9999", "--token", TEST_TOKEN]
        )

        rest_api.main()

        assert captured["host"] == "0.0.0.0"
        assert captured["port"] == 9999
