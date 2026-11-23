"""Tests for wps_attack.py — WPS PIN Brute Force."""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from wps_attack import WPSAttack  # noqa: E402


@pytest.fixture
def mock_interface():
    return "wlan0mon"


@pytest.fixture
def mock_bssid():
    return "AA:BB:CC:DD:EE:FF"


@pytest.fixture
def attacker(mock_interface, mock_bssid):
    return WPSAttack(interface=mock_interface, target_bssid=mock_bssid)


class TestWPSAttackInit:
    def test_default_init(self, mock_interface, mock_bssid):
        a = WPSAttack(interface=mock_interface, target_bssid=mock_bssid)
        assert a.interface == mock_interface
        assert a.target_bssid == mock_bssid.upper()
        assert a.method == "reaver"
        assert a.timeout == 300
        assert a.pixie_dust is False
        assert a.pin is None

    def test_custom_init(self, mock_interface, mock_bssid):
        a = WPSAttack(
            interface=mock_interface,
            target_bssid=mock_bssid,
            channel=6,
            method="bully",
            timeout=600,
            pixie_dust=True,
            pin="12345670",
        )
        assert a.channel == 6
        assert a.method == "bully"
        assert a.timeout == 600
        assert a.pixie_dust is True
        assert a.pin == "12345670"

    def test_bssid_uppercase(self, mock_interface):
        a = WPSAttack(interface=mock_interface, target_bssid="aa:bb:cc:dd:ee:ff")
        assert a.target_bssid == "AA:BB:CC:DD:EE:FF"


class TestCheckTools:
    @patch("shutil.which")
    def test_all_tools_found(self, mock_which, attacker):
        mock_which.return_value = "/usr/bin/reaver"
        result = attacker.check_tools()
        assert result["reaver"] is True
        assert result["bully"] is True
        assert result["wash"] is True

    @patch("shutil.which")
    def test_no_tools_found(self, mock_which, attacker):
        mock_which.return_value = None
        result = attacker.check_tools()
        assert result["reaver"] is False
        assert result["bully"] is False
        assert result["wash"] is False

    @patch("shutil.which")
    def test_partial_tools(self, mock_which, attacker):
        def which_side_effect(tool):
            return "/usr/bin/reaver" if tool == "reaver" else None
        mock_which.side_effect = which_side_effect
        result = attacker.check_tools()
        assert result["reaver"] is True
        assert result["bully"] is False


class TestScanWPSTargets:
    @patch("shutil.which", return_value="/usr/bin/wash")
    @patch("subprocess.run")
    def test_scan_parses_output(self, mock_run, mock_which, attacker):
        mock_run.return_value = MagicMock(
            stdout="BSSID              Ch  dBm  WPS  Lck  ESSID\n"
                   "---\n"
                   "AA:BB:CC:DD:EE:FF  6   -50  2.0  No   TestNetwork\n",
            returncode=0,
        )
        targets = attacker.scan_wps_targets()
        assert len(targets) == 1
        assert targets[0]["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert targets[0]["ssid"] == "TestNetwork"

    @patch("shutil.which", return_value=None)
    def test_scan_no_wash(self, mock_which, attacker):
        targets = attacker.scan_wps_targets()
        assert targets == []

    @patch("shutil.which", return_value="/usr/bin/wash")
    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_scan_wash_not_found(self, mock_run, mock_which, attacker):
        targets = attacker.scan_wps_targets()
        assert targets == []

    @patch("shutil.which", return_value="/usr/bin/wash")
    @patch("subprocess.run")
    def test_scan_empty_result(self, mock_run, mock_which, attacker):
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        targets = attacker.scan_wps_targets()
        assert targets == []


class TestRunTool:
    @patch("subprocess.Popen")
    def test_run_reaver_success(self, mock_popen, attacker):
        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [
            b"[+] Trying pin 12345670\n",
            b"[+] WPS PIN: '12345670'\n",
            b"[+] WPA PSK: 'MyPassword123'\n",
            b"",
        ]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [None, None, None, 0, 0]
        mock_popen.return_value = mock_proc

        result = attacker._run_reaver()
        assert result["pin"] == "12345670"
        assert result["psk"] == "MyPassword123"
        assert result["status"] == "success"

    @patch("subprocess.Popen")
    def test_run_bully(self, mock_popen, mock_interface, mock_bssid):
        a = WPSAttack(interface=mock_interface, target_bssid=mock_bssid, method="bully")
        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [b"", b""]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [None, 0, 0]
        mock_popen.return_value = mock_proc

        result = a._run_bully()
        assert result["status"] == "failed"

    @patch("subprocess.Popen", side_effect=FileNotFoundError)
    def test_run_tool_not_found(self, mock_popen, attacker):
        result = attacker._run_reaver()
        assert result["status"] == "tool_not_found"


class TestAttack:
    @patch.object(WPSAttack, "_run_reaver")
    def test_attack_reaver(self, mock_run, attacker):
        mock_run.return_value = {"status": "success", "pin": "12345670", "psk": "pass"}
        result = attacker.attack()
        assert result["status"] == "success"
        assert result["method"] == "reaver"
        mock_run.assert_called_once()

    @patch.object(WPSAttack, "_run_bully")
    def test_attack_bully(self, mock_run, mock_interface, mock_bssid):
        a = WPSAttack(interface=mock_interface, target_bssid=mock_bssid, method="bully")
        mock_run.return_value = {"status": "failed", "pin": None, "psk": None}
        result = a.attack()
        assert result["method"] == "bully"
        mock_run.assert_called_once()

    @patch.object(WPSAttack, "_run_pixie_dust")
    def test_attack_pixie_dust(self, mock_run, mock_interface, mock_bssid):
        a = WPSAttack(interface=mock_interface, target_bssid=mock_bssid, method="pixie-dust")
        mock_run.return_value = {"status": "success", "pin": "12345670", "psk": None}
        result = a.attack()
        assert result["method"] == "pixie-dust"
        mock_run.assert_called_once()

    def test_attack_unknown_method(self, mock_interface, mock_bssid):
        a = WPSAttack(interface=mock_interface, target_bssid=mock_bssid, method="unknown")
        result = a.attack()
        assert result["status"] == "error"


class TestGetStatus:
    def test_initial_status(self, attacker):
        status = attacker.get_status()
        assert status["status"] == "idle"
        assert status["pin"] is None
        assert status["psk"] is None


class TestStop:
    def test_stop_sets_event(self, attacker):
        attacker.stop()
        assert attacker._stop_event.is_set()

    @patch("subprocess.Popen")
    def test_stop_terminates_process(self, mock_popen, attacker):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        attacker._process = mock_proc
        attacker.stop()
        mock_proc.terminate.assert_called_once()


class TestSaveResult:
    def test_save_result_creates_file(self, attacker):
        with tempfile.TemporaryDirectory() as tmpdir:
            attacker.output_dir = tmpdir
            attacker._result["start_time"] = "2024-01-01 00:00:00"
            attacker._result["end_time"] = "2024-01-01 00:05:00"
            attacker._save_result({"pin": "12345670", "psk": "pass123"})
            files = os.listdir(tmpdir)
            assert len(files) == 1
            assert files[0].startswith("wps_")
