"""Tests for hoover_web.py — New tool API endpoints (packet_replay, wps_attack,
network_mapper, ble_scanner, pentest_workflow)."""

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.modules.setdefault("psutil", MagicMock(
    cpu_percent=MagicMock(return_value=5.0),
    virtual_memory=MagicMock(return_value=MagicMock(percent=30.0)),
))
sys.modules.setdefault("flask_socketio", MagicMock())

from hoover_web import app, _generate_auth_password, tool_status  # noqa: E402
import hoover_web  # noqa: E402


@pytest.fixture(autouse=True)
def _setup_app(tmp_path, monkeypatch):
    app.config["TESTING"] = True
    app.config["SECRET_KEY"] = "test-secret-key"
    ssid_dir = tmp_path / "ssid_files"
    ssid_dir.mkdir()
    monkeypatch.setattr(hoover_web, "SSID_FILES_DIR", ssid_dir)
    password = _generate_auth_password()
    app.config["_test_password"] = password
    for key in tool_status:
        tool_status[key]['running'] = False
        tool_status[key]['pid'] = None
        tool_status[key]['interface'] = None


@pytest.fixture
def auth_client():
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["authenticated"] = True
        sess["csrf_token"] = "test-csrf-token"
    return client


def _post(client, url, data=None):
    payload = data or {}
    return client.post(
        url,
        data=json.dumps(payload),
        content_type="application/json",
        headers={"X-CSRF-Token": "test-csrf-token"},
    )


class TestNewToolsInStatus:
    def test_new_tools_in_tool_status(self):
        assert 'packet_replay' in tool_status
        assert 'wps_attack' in tool_status
        assert 'network_mapper' in tool_status
        assert 'ble_scanner' in tool_status
        assert 'pentest_workflow' in tool_status

    def test_new_tools_initial_state(self):
        for tool in ['packet_replay', 'wps_attack', 'network_mapper', 'ble_scanner', 'pentest_workflow']:
            assert tool_status[tool]['running'] is False
            assert tool_status[tool]['pid'] is None


class TestPacketReplayEndpoints:
    @patch("hoover_web.subprocess.Popen")
    def test_start(self, mock_popen, auth_client):
        mock_proc = MagicMock()
        mock_proc.pid = 1234
        mock_popen.return_value = mock_proc
        resp = _post(auth_client, "/api/packet-replay/start", {"interface": "wlan0mon"})
        data = resp.get_json()
        assert data["success"] is True
        assert data["pid"] == 1234

    @patch("hoover_web.subprocess.Popen")
    def test_start_already_running(self, mock_popen, auth_client):
        tool_status['packet_replay']['running'] = True
        resp = _post(auth_client, "/api/packet-replay/start", {"interface": "wlan0mon"})
        data = resp.get_json()
        assert data["success"] is False

    def test_start_no_interface(self, auth_client):
        resp = _post(auth_client, "/api/packet-replay/start", {"interface": ""})
        assert resp.status_code == 400

    def test_stop_not_running(self, auth_client):
        resp = _post(auth_client, "/api/packet-replay/stop", {})
        data = resp.get_json()
        assert data["success"] is False

    def test_stop_running(self, auth_client):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        tool_status['packet_replay']['running'] = True
        hoover_web.active_processes['packet_replay'] = mock_proc
        resp = _post(auth_client, "/api/packet-replay/stop", {})
        data = resp.get_json()
        assert data["success"] is True
        assert tool_status['packet_replay']['running'] is False


class TestWPSAttackEndpoints:
    @patch("hoover_web.subprocess.Popen")
    def test_start(self, mock_popen, auth_client):
        mock_proc = MagicMock()
        mock_proc.pid = 2345
        mock_popen.return_value = mock_proc
        resp = _post(auth_client, "/api/wps-attack/start",
                     {"interface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:FF"})
        data = resp.get_json()
        assert data["success"] is True

    def test_start_no_bssid(self, auth_client):
        resp = _post(auth_client, "/api/wps-attack/start", {"interface": "wlan0mon", "bssid": ""})
        assert resp.status_code == 400

    def test_start_invalid_mac(self, auth_client):
        resp = _post(auth_client, "/api/wps-attack/start",
                     {"interface": "wlan0mon", "bssid": "not-a-mac"})
        assert resp.status_code == 400

    def test_stop_not_running(self, auth_client):
        resp = _post(auth_client, "/api/wps-attack/stop", {})
        data = resp.get_json()
        assert data["success"] is False


class TestNetworkMapperEndpoints:
    @patch("hoover_web.subprocess.Popen")
    def test_start(self, mock_popen, auth_client):
        mock_proc = MagicMock()
        mock_proc.pid = 3456
        mock_popen.return_value = mock_proc
        resp = _post(auth_client, "/api/network-mapper/start",
                     {"interface": "eth0", "target_range": "10.0.0.0/24"})
        data = resp.get_json()
        assert data["success"] is True

    @patch("hoover_web.subprocess.Popen")
    def test_start_no_port_scan(self, mock_popen, auth_client):
        mock_proc = MagicMock()
        mock_proc.pid = 3457
        mock_popen.return_value = mock_proc
        resp = _post(auth_client, "/api/network-mapper/start",
                     {"interface": "eth0", "port_scan": False})
        data = resp.get_json()
        assert data["success"] is True

    def test_stop_not_running(self, auth_client):
        resp = _post(auth_client, "/api/network-mapper/stop", {})
        data = resp.get_json()
        assert data["success"] is False


class TestBLEScannerEndpoints:
    @patch("hoover_web.subprocess.Popen")
    def test_start(self, mock_popen, auth_client):
        mock_proc = MagicMock()
        mock_proc.pid = 4567
        mock_popen.return_value = mock_proc
        resp = _post(auth_client, "/api/ble-scanner/start", {"scan_time": 20})
        data = resp.get_json()
        assert data["success"] is True

    @patch("hoover_web.subprocess.Popen")
    def test_start_with_filters(self, mock_popen, auth_client):
        mock_proc = MagicMock()
        mock_proc.pid = 4568
        mock_popen.return_value = mock_proc
        resp = _post(auth_client, "/api/ble-scanner/start",
                     {"scan_time": 10, "service_scan": True, "filter_name": "Smart"})
        data = resp.get_json()
        assert data["success"] is True

    def test_stop_not_running(self, auth_client):
        resp = _post(auth_client, "/api/ble-scanner/stop", {})
        data = resp.get_json()
        assert data["success"] is False


class TestPentestWorkflowEndpoints:
    @patch("hoover_web.subprocess.Popen")
    def test_start(self, mock_popen, auth_client):
        mock_proc = MagicMock()
        mock_proc.pid = 5678
        mock_popen.return_value = mock_proc
        resp = _post(auth_client, "/api/pentest-workflow/start", {"interface": "wlan0mon"})
        data = resp.get_json()
        assert data["success"] is True

    @patch("hoover_web.subprocess.Popen")
    def test_start_with_options(self, mock_popen, auth_client):
        mock_proc = MagicMock()
        mock_proc.pid = 5679
        mock_popen.return_value = mock_proc
        resp = _post(auth_client, "/api/pentest-workflow/start",
                     {"interface": "wlan0mon", "bssid": "AA:BB:CC:DD:EE:FF",
                      "no_deauth": True, "skip_wps": True})
        data = resp.get_json()
        assert data["success"] is True

    def test_start_invalid_bssid(self, auth_client):
        resp = _post(auth_client, "/api/pentest-workflow/start",
                     {"interface": "wlan0mon", "bssid": "invalid"})
        assert resp.status_code == 400

    def test_stop_not_running(self, auth_client):
        resp = _post(auth_client, "/api/pentest-workflow/stop", {})
        data = resp.get_json()
        assert data["success"] is False

    def test_start_no_interface(self, auth_client):
        resp = _post(auth_client, "/api/pentest-workflow/start", {"interface": ""})
        assert resp.status_code == 400


class TestAuthRequired:
    def test_new_endpoints_require_auth(self):
        client = app.test_client()
        endpoints = [
            "/api/packet-replay/start", "/api/packet-replay/stop",
            "/api/wps-attack/start", "/api/wps-attack/stop",
            "/api/network-mapper/start", "/api/network-mapper/stop",
            "/api/ble-scanner/start", "/api/ble-scanner/stop",
            "/api/pentest-workflow/start", "/api/pentest-workflow/stop",
        ]
        for endpoint in endpoints:
            resp = client.post(
                endpoint,
                data=json.dumps({}),
                content_type="application/json",
            )
            assert resp.status_code == 401, f"{endpoint} should require auth"
