"""Tests for captive_portal.py — Captive Portal."""

import os
from unittest.mock import MagicMock, patch

import pytest

from captive_portal import PORTAL_TEMPLATES, CaptivePortal  # noqa: E402

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def portal(mock_interface, tmp_path):
    return CaptivePortal(
        interface=mock_interface,
        ssid="TestNet",
        log_file=str(tmp_path / "creds.log"),
    )


@pytest.fixture
def portal_app(portal):
    """Return a Flask test client for the portal app."""
    app = portal._create_portal_app()
    app.config["TESTING"] = True
    return app.test_client()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCaptivePortalInit:
    def test_defaults(self, mock_interface):
        p = CaptivePortal(interface=mock_interface)
        assert p.interface == mock_interface
        assert p.ssid == "Free-WiFi"
        assert p.channel == 6
        assert p.portal_template == "default"
        assert p.dns_redirect is True
        assert p.captured_creds == []

    def test_custom_params(self, mock_interface):
        p = CaptivePortal(
            interface=mock_interface, ssid="Hotel",
            channel=11, portal_template="hotel",
        )
        assert p.ssid == "Hotel"
        assert p.channel == 11
        assert p.portal_template == "hotel"


class TestPortalTemplates:
    def test_all_templates_have_required_keys(self):
        for name, tmpl in PORTAL_TEMPLATES.items():
            assert "title" in tmpl, f"{name} missing title"
            assert "heading" in tmpl, f"{name} missing heading"
            assert "fields" in tmpl, f"{name} missing fields"
            assert "button" in tmpl, f"{name} missing button"
            assert len(tmpl["fields"]) > 0, f"{name} has no fields"

    def test_default_has_email_password(self):
        fields = [f["name"] for f in PORTAL_TEMPLATES["default"]["fields"]]
        assert "email" in fields
        assert "password" in fields

    def test_hotel_has_room_fields(self):
        fields = [f["name"] for f in PORTAL_TEMPLATES["hotel"]["fields"]]
        assert "room_number" in fields
        assert "last_name" in fields

    def test_coffee_has_email(self):
        fields = [f["name"] for f in PORTAL_TEMPLATES["coffee"]["fields"]]
        assert "email" in fields


class TestGeneratePortalHTML:
    def test_default_html(self, portal):
        html = portal._generate_portal_html()
        assert "WiFi Login" in html
        assert "email" in html
        assert "password" in html
        assert "<form" in html
        assert "/login" in html

    def test_hotel_html(self, mock_interface):
        p = CaptivePortal(interface=mock_interface, portal_template="hotel")
        html = p._generate_portal_html()
        assert "Hotel Guest WiFi" in html
        assert "room_number" in html

    def test_coffee_html(self, mock_interface):
        p = CaptivePortal(interface=mock_interface, portal_template="coffee")
        html = p._generate_portal_html()
        assert "Free WiFi" in html


class TestPortalApp:
    def test_index_returns_200(self, portal_app):
        resp = portal_app.get("/")
        assert resp.status_code == 200
        assert b"WiFi Login" in resp.data

    def test_login_captures_creds(self, portal, portal_app):
        resp = portal_app.post("/login", data={
            "email": "test@example.com",
            "password": "secret123",
        })
        assert resp.status_code == 200
        assert b"Connected" in resp.data
        assert len(portal.captured_creds) == 1
        assert portal.captured_creds[0]["email"] == "test@example.com"

    def test_captive_portal_redirect(self, portal_app):
        resp = portal_app.get("/generate_204")
        assert resp.status_code == 302
        assert "/" in resp.headers.get("Location", "")

    def test_hotspot_detect_redirect(self, portal_app):
        resp = portal_app.get("/hotspot-detect.html")
        assert resp.status_code == 302


class TestLogCredentials:
    def test_log_writes_file(self, portal, tmp_path):
        portal._log_credentials({
            "timestamp": "2024-01-01 12:00:00",
            "source_ip": "192.168.100.10",
            "email": "test@example.com",
        })
        assert os.path.exists(portal.log_file)
        with open(portal.log_file) as f:
            content = f.read()
        assert "test@example.com" in content

    def test_log_appends_to_list(self, portal):
        portal._log_credentials({"timestamp": "now", "email": "a@b.com"})
        portal._log_credentials({"timestamp": "now", "email": "c@d.com"})
        assert len(portal.captured_creds) == 2


class TestSetupAP:
    @patch("captive_portal.subprocess.Popen")
    @patch("captive_portal.subprocess.run")
    def test_setup_creates_hostapd(self, mock_run, mock_popen, portal):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc
        result = portal._setup_ap()
        assert result is True
        mock_popen.assert_called_once()
        assert portal._hostapd_proc is not None

    @patch("captive_portal.subprocess.Popen", side_effect=FileNotFoundError)
    @patch("captive_portal.subprocess.run")
    def test_setup_ap_missing_hostapd(self, mock_run, mock_popen, portal):
        result = portal._setup_ap()
        assert result is False


class TestSetupDNS:
    @patch("captive_portal.subprocess.Popen")
    def test_setup_creates_dnsmasq(self, mock_popen, portal):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc
        result = portal._setup_dns()
        assert result is True

    def test_no_dns_redirect(self, mock_interface):
        p = CaptivePortal(interface=mock_interface, dns_redirect=False)
        result = p._setup_dns()
        assert result is True


class TestCleanup:
    def test_stop_kills_processes(self, portal):
        portal._hostapd_proc = MagicMock()
        portal._dnsmasq_proc = MagicMock()
        with patch.object(portal, "_cleanup_iptables"):
            portal.stop()
        portal._hostapd_proc.terminate.assert_called_once()
        portal._dnsmasq_proc.terminate.assert_called_once()

    @patch("captive_portal.subprocess.run")
    def test_iptables_setup_and_cleanup(self, mock_run, portal):
        portal._setup_iptables()
        assert mock_run.call_count >= 2
        mock_run.reset_mock()
        portal._cleanup_iptables()
        assert mock_run.call_count >= 2
