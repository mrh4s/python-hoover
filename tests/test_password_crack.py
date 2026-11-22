"""Tests for password_crack.py — hashcat/aircrack-ng cracking integration."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from password_crack import PasswordCracker, main  # noqa: E402


@pytest.fixture
def capture_file(tmp_path):
    f = tmp_path / "capture.pcap"
    # libpcap magic bytes
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    return str(f)


@pytest.fixture
def cracker(capture_file, tmp_path):
    return PasswordCracker(
        capture_file=capture_file,
        output_dir=str(tmp_path / "results"),
    )


class TestInit:
    def test_defaults(self, capture_file):
        c = PasswordCracker(capture_file=capture_file)
        assert c.capture_file == capture_file
        assert c.target_bssid is None
        assert c.wordlist == "/usr/share/wordlists/rockyou.txt"
        assert c.tool == "auto"
        assert c.hashcat_mode is None
        assert c.rules_file is None
        assert c.output_dir == "crack_results"
        assert c.timeout == 3600
        assert c.gpu is True

    def test_custom_init(self, capture_file):
        c = PasswordCracker(
            capture_file=capture_file,
            target_bssid="aa:bb:cc:dd:ee:ff",
            wordlist="/tmp/words.txt",
            tool="hashcat",
            hashcat_mode=2500,
            rules_file="best64.rule",
            output_dir="out",
            timeout=60,
            gpu=False,
        )
        assert c.target_bssid == "AA:BB:CC:DD:EE:FF"
        assert c.wordlist == "/tmp/words.txt"
        assert c.tool == "hashcat"
        assert c.hashcat_mode == 2500
        assert c.rules_file == "best64.rule"
        assert c.output_dir == "out"
        assert c.timeout == 60
        assert c.gpu is False

    def test_invalid_bssid_raises(self, capture_file):
        with pytest.raises(ValueError):
            PasswordCracker(capture_file=capture_file, target_bssid="not-a-mac")

    def test_initial_result_state(self, cracker):
        status = cracker.get_status()
        assert status["status"] == "idle"
        assert status["cracked"] is False
        assert status["password"] is None


class TestCheckTools:
    @patch("shutil.which")
    def test_all_found(self, mock_which, cracker):
        mock_which.return_value = "/usr/bin/tool"
        result = cracker.check_tools()
        assert result == {
            "hashcat": True, "aircrack": True,
            "hcxpcapngtool": True, "cap2hccapx": True,
        }

    @patch("shutil.which")
    def test_none_found(self, mock_which, cracker):
        mock_which.return_value = None
        result = cracker.check_tools()
        assert result == {
            "hashcat": False, "aircrack": False,
            "hcxpcapngtool": False, "cap2hccapx": False,
        }

    @patch("shutil.which")
    def test_partial(self, mock_which, cracker):
        mock_which.side_effect = lambda t: "/usr/bin/hashcat" if t == "hashcat" else None
        result = cracker.check_tools()
        assert result["hashcat"] is True
        assert result["aircrack"] is False


class TestDetectCaptureFormat:
    def test_22000_extension(self, cracker, tmp_path):
        f = tmp_path / "x.22000"
        f.write_text("hash")
        assert cracker.detect_capture_format(str(f)) == "hc22000"

    def test_hc22000_extension(self, cracker, tmp_path):
        f = tmp_path / "x.hc22000"
        f.write_text("hash")
        assert cracker.detect_capture_format(str(f)) == "hc22000"

    def test_hccapx_extension(self, cracker, tmp_path):
        f = tmp_path / "x.hccapx"
        f.write_bytes(b"\x00")
        assert cracker.detect_capture_format(str(f)) == "hccapx"

    def test_pcapng_extension(self, cracker, tmp_path):
        f = tmp_path / "x.pcapng"
        f.write_bytes(b"\x0a\x0d\x0d\x0a")
        assert cracker.detect_capture_format(str(f)) == "pcapng"

    def test_cap_extension(self, cracker, tmp_path):
        f = tmp_path / "x.cap"
        f.write_bytes(b"\xd4\xc3\xb2\xa1")
        assert cracker.detect_capture_format(str(f)) == "cap"

    def test_pcap_extension(self, cracker, tmp_path):
        f = tmp_path / "x.pcap"
        f.write_bytes(b"\xd4\xc3\xb2\xa1")
        assert cracker.detect_capture_format(str(f)) == "pcap"

    def test_magic_bytes_pcapng_no_extension(self, cracker, tmp_path):
        f = tmp_path / "noext"
        f.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 10)
        assert cracker.detect_capture_format(str(f)) == "pcapng"

    def test_magic_bytes_pcap_no_extension(self, cracker, tmp_path):
        f = tmp_path / "noext2"
        f.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 10)
        assert cracker.detect_capture_format(str(f)) == "pcap"

    def test_unknown_format(self, cracker, tmp_path):
        f = tmp_path / "noext3"
        f.write_bytes(b"\xff\xff\xff\xff")
        assert cracker.detect_capture_format(str(f)) == "unknown"

    def test_unreadable_file_returns_unknown(self, cracker, tmp_path):
        missing = str(tmp_path / "does_not_exist")
        assert cracker.detect_capture_format(missing) == "unknown"


class TestIsWepCapture:
    def test_ivs_extension(self, cracker, tmp_path):
        f = tmp_path / "x.ivs"
        f.write_bytes(b"\x00")
        assert cracker.is_wep_capture(str(f)) is True

    def test_non_wep_pcap(self, cracker, capture_file):
        assert cracker.is_wep_capture(capture_file) is False


class TestConvertToHashcat:
    @patch("subprocess.run")
    @patch("shutil.which")
    def test_hcxpcapngtool_preferred(self, mock_which, mock_run, cracker, capture_file, tmp_path):
        mock_which.side_effect = lambda t: f"/usr/bin/{t}" if t == "hcxpcapngtool" else None
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        out_dir = cracker.output_dir
        expected = os.path.join(out_dir, "capture.22000")

        def fake_run(cmd, **kwargs):
            # simulate the tool creating the output file
            os.makedirs(out_dir, exist_ok=True)
            with open(expected, "w") as f:
                f.write("hash")
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = fake_run
        result = cracker.convert_to_hashcat(capture_file)
        assert result == expected

    @patch("subprocess.run")
    @patch("shutil.which")
    def test_cap2hccapx_fallback(self, mock_which, mock_run, cracker, capture_file):
        mock_which.side_effect = lambda t: f"/usr/bin/{t}" if t == "cap2hccapx" else None
        out_dir = cracker.output_dir
        expected = os.path.join(out_dir, "capture.hccapx")

        def fake_run(cmd, **kwargs):
            os.makedirs(out_dir, exist_ok=True)
            with open(expected, "w") as f:
                f.write("hash")
            return MagicMock(returncode=0, stderr="")

        mock_run.side_effect = fake_run
        result = cracker.convert_to_hashcat(capture_file)
        assert result == expected

    @patch("shutil.which", return_value=None)
    def test_no_converter_available(self, mock_which, cracker, capture_file):
        result = cracker.convert_to_hashcat(capture_file)
        assert result is None

    @patch("subprocess.run")
    @patch("shutil.which")
    def test_conversion_failure_returns_none(self, mock_which, mock_run, cracker, capture_file):
        mock_which.side_effect = lambda t: f"/usr/bin/{t}" if t == "hcxpcapngtool" else None
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        result = cracker.convert_to_hashcat(capture_file)
        assert result is None


class TestConvertToAircrack:
    def test_pcap_returned_unchanged(self, cracker, capture_file):
        assert cracker.convert_to_aircrack(capture_file) == capture_file

    def test_pcapng_returned_unchanged(self, cracker, tmp_path):
        f = tmp_path / "x.pcapng"
        f.write_bytes(b"\x0a\x0d\x0d\x0a")
        assert cracker.convert_to_aircrack(str(f)) == str(f)

    def test_hc22000_returns_none(self, cracker, tmp_path):
        f = tmp_path / "x.22000"
        f.write_text("hash")
        assert cracker.convert_to_aircrack(str(f)) is None


class TestParseHashcatOutput:
    def test_cracked_status(self, cracker):
        output = (
            "Session..........: hashcat\n"
            "Status...........: Cracked\n"
            "Recovered........: 1/1 (100.00%)\n"
            "Progress.........: 14344385/14344385 (100.00%)\n"
            "Speed.#1.........:  1337 H/s\n"
            "abcdef0123456789abcdef0123456789abcdef01*AABBCC*AABBCCDDEEFF:SuperSecret1\n"
        )
        result = cracker._parse_hashcat_output(output)
        assert result["cracked"] is True
        assert result["password"] == "SuperSecret1"
        assert result["status_text"] == "Cracked"
        assert "1337" in result["speed"]
        assert result["recovered"] == "1/1 (100.00%)"

    def test_not_cracked(self, cracker):
        output = (
            "Status...........: Exhausted\n"
            "Recovered........: 0/1 (0.00%)\n"
        )
        result = cracker._parse_hashcat_output(output)
        assert result["cracked"] is False
        assert result["password"] is None
        assert result["status_text"] == "Exhausted"

    def test_empty_output(self, cracker):
        result = cracker._parse_hashcat_output("")
        assert result["cracked"] is False
        assert result["password"] is None


class TestParseAircrackOutput:
    def test_key_found(self, cracker):
        output = (
            "      [00:00:12] 1234/14344392 keys tested (102.34 k/s)\n"
            "\n"
            "                  KEY FOUND! [ password123 ]\n"
        )
        result = cracker._parse_aircrack_output(output)
        assert result["cracked"] is True
        assert result["password"] == "password123"
        assert result["tested_keys"] == 1234
        assert result["total_keys"] == 14344392
        assert result["speed"] == "102.34 k/s"

    def test_key_not_found(self, cracker):
        output = "      [00:01:00] 5000/14344392 keys tested (99.99 k/s)\n"
        result = cracker._parse_aircrack_output(output)
        assert result["cracked"] is False
        assert result["password"] is None
        assert result["tested_keys"] == 5000

    def test_empty_output(self, cracker):
        result = cracker._parse_aircrack_output("")
        assert result["cracked"] is False
        assert result["password"] is None


class TestRunHashcat:
    @patch("shutil.which", return_value=None)
    def test_tool_not_found(self, mock_which, cracker, tmp_path):
        f = tmp_path / "x.22000"
        f.write_text("hash")
        result = cracker.run_hashcat(str(f))
        assert result["status"] == "tool_not_found"
        assert result["cracked"] is False

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/hashcat")
    def test_success(self, mock_which, mock_popen, cracker, tmp_path):
        f = tmp_path / "x.22000"
        f.write_text("hash")

        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [
            b"Status...........: Cracked\n",
            b"abcdef0123456789abcdef0123456789abcdef01*AA*BB:MyPassword\n",
            b"",
        ]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [None, None, 0, 0]
        mock_popen.return_value = mock_proc

        result = cracker.run_hashcat(str(f))
        assert result["cracked"] is True
        assert result["password"] == "MyPassword"
        assert result["tool"] == "hashcat"

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/hashcat")
    def test_not_cracked(self, mock_which, mock_popen, cracker, tmp_path):
        f = tmp_path / "x.22000"
        f.write_text("hash")

        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [b"Status...........: Exhausted\n", b""]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [None, 0, 0]
        mock_popen.return_value = mock_proc

        result = cracker.run_hashcat(str(f))
        assert result["cracked"] is False
        assert result["status"] == "not_cracked"

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/hashcat")
    def test_timeout(self, mock_which, mock_popen, tmp_path):
        f = tmp_path / "x.22000"
        f.write_text("hash")

        c = PasswordCracker(capture_file=str(f), output_dir=str(tmp_path / "out"), timeout=0)

        mock_proc = MagicMock()
        # poll() always returns None -> process still running -> timeout triggers
        mock_proc.poll.return_value = None
        mock_proc.stdout.readline.return_value = b""
        mock_proc.stdout.read.return_value = b""
        mock_popen.return_value = mock_proc

        result = c.run_hashcat(str(f))
        assert result["status"] == "timeout"
        mock_proc.terminate.assert_called()

    @patch("subprocess.Popen", side_effect=FileNotFoundError)
    @patch("shutil.which", return_value="/usr/bin/hashcat")
    def test_popen_file_not_found(self, mock_which, mock_popen, cracker, tmp_path):
        f = tmp_path / "x.22000"
        f.write_text("hash")
        result = cracker.run_hashcat(str(f))
        assert result["status"] == "tool_not_found"

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/hashcat")
    def test_explicit_mode_used(self, mock_which, mock_popen, tmp_path):
        f = tmp_path / "x.hccapx"
        f.write_bytes(b"\x00")
        c = PasswordCracker(capture_file=str(f), hashcat_mode=9999,
                             output_dir=str(tmp_path / "out"))

        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [b""]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [0, 0]
        mock_popen.return_value = mock_proc

        c.run_hashcat(str(f))
        called_cmd = mock_popen.call_args[0][0]
        assert "9999" in called_cmd

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/hashcat")
    def test_rules_file_included(self, mock_which, mock_popen, tmp_path):
        f = tmp_path / "x.22000"
        f.write_text("hash")
        c = PasswordCracker(capture_file=str(f), rules_file="best64.rule",
                             output_dir=str(tmp_path / "out"))

        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [b""]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [0, 0]
        mock_popen.return_value = mock_proc

        c.run_hashcat(str(f))
        called_cmd = mock_popen.call_args[0][0]
        assert "-r" in called_cmd
        assert "best64.rule" in called_cmd

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/hashcat")
    def test_no_gpu_uses_cpu_device(self, mock_which, mock_popen, tmp_path):
        f = tmp_path / "x.22000"
        f.write_text("hash")
        c = PasswordCracker(capture_file=str(f), gpu=False, output_dir=str(tmp_path / "out"))

        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [b""]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [0, 0]
        mock_popen.return_value = mock_proc

        c.run_hashcat(str(f))
        called_cmd = mock_popen.call_args[0][0]
        idx = called_cmd.index("-D")
        assert called_cmd[idx + 1] == "1"


class TestRunAircrack:
    @patch("shutil.which", return_value=None)
    def test_tool_not_found(self, mock_which, cracker, capture_file):
        result = cracker.run_aircrack(capture_file)
        assert result["status"] == "tool_not_found"
        assert result["cracked"] is False

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/aircrack-ng")
    def test_success(self, mock_which, mock_popen, cracker, capture_file):
        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [
            b"      [00:00:12] 1234/14344392 keys tested (102.34 k/s)\n",
            b"                  KEY FOUND! [ password123 ]\n",
            b"",
        ]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [None, None, 0, 0]
        mock_popen.return_value = mock_proc

        result = cracker.run_aircrack(capture_file)
        assert result["cracked"] is True
        assert result["password"] == "password123"
        assert result["tool"] == "aircrack"

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/aircrack-ng")
    def test_not_cracked(self, mock_which, mock_popen, cracker, capture_file):
        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [b""]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [0, 0]
        mock_popen.return_value = mock_proc

        result = cracker.run_aircrack(capture_file)
        assert result["cracked"] is False
        assert result["status"] == "not_cracked"

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/aircrack-ng")
    def test_bssid_passed(self, mock_which, mock_popen, capture_file, tmp_path):
        c = PasswordCracker(capture_file=capture_file, target_bssid="AA:BB:CC:DD:EE:FF",
                             output_dir=str(tmp_path / "out"))
        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [b""]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [0, 0]
        mock_popen.return_value = mock_proc

        c.run_aircrack(capture_file)
        called_cmd = mock_popen.call_args[0][0]
        assert "-b" in called_cmd
        assert "AA:BB:CC:DD:EE:FF" in called_cmd

    @patch("subprocess.Popen")
    @patch("shutil.which", return_value="/usr/bin/aircrack-ng")
    def test_wep_mode_flag(self, mock_which, mock_popen, tmp_path):
        f = tmp_path / "x.ivs"
        f.write_bytes(b"\x00")
        c = PasswordCracker(capture_file=str(f), output_dir=str(tmp_path / "out"))
        mock_proc = MagicMock()
        mock_proc.stdout.readline.side_effect = [b""]
        mock_proc.stdout.read.return_value = b""
        mock_proc.poll.side_effect = [0, 0]
        mock_popen.return_value = mock_proc

        c.run_aircrack(str(f))
        called_cmd = mock_popen.call_args[0][0]
        idx = called_cmd.index("-a")
        assert called_cmd[idx + 1] == "1"


class TestAutoToolSelection:
    @patch("shutil.which")
    def test_gpu_prefers_hashcat(self, mock_which, cracker):
        mock_which.side_effect = lambda t: f"/usr/bin/{t}" if t in ("hashcat", "aircrack-ng") else None
        cracker.gpu = True
        assert cracker._select_tool() == "hashcat"

    @patch("shutil.which")
    def test_no_gpu_prefers_aircrack(self, mock_which, cracker):
        mock_which.side_effect = lambda t: f"/usr/bin/{t}" if t in ("hashcat", "aircrack-ng") else None
        cracker.gpu = False
        assert cracker._select_tool() == "aircrack"

    @patch("shutil.which")
    def test_explicit_tool_overrides_auto(self, mock_which, capture_file, tmp_path):
        c = PasswordCracker(capture_file=capture_file, tool="aircrack",
                             output_dir=str(tmp_path / "out"))
        mock_which.return_value = "/usr/bin/hashcat"
        assert c._select_tool() == "aircrack"

    @patch("shutil.which", return_value=None)
    def test_falls_back_when_aircrack_missing(self, mock_which, cracker):
        cracker.gpu = False
        assert cracker._select_tool() == "hashcat"


class TestStop:
    def test_stop_sets_event_and_terminates(self, cracker):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        cracker._process = mock_proc
        cracker.stop()
        assert cracker._stop_event.is_set()
        mock_proc.terminate.assert_called_once()

    def test_stop_no_process(self, cracker):
        cracker._process = None
        cracker.stop()  # should not raise
        assert cracker._stop_event.is_set()

    def test_stop_kills_on_terminate_timeout(self, cracker):
        import subprocess
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_proc.wait.side_effect = subprocess.TimeoutExpired(cmd="x", timeout=5)
        cracker._process = mock_proc
        cracker.stop()
        mock_proc.kill.assert_called_once()


class TestGetStatus:
    def test_get_status_returns_copy(self, cracker):
        status1 = cracker.get_status()
        status1["status"] = "mutated"
        status2 = cracker.get_status()
        assert status2["status"] == "idle"


class TestStart:
    def test_missing_capture_file(self, tmp_path):
        c = PasswordCracker(capture_file=str(tmp_path / "missing.pcap"),
                             output_dir=str(tmp_path / "out"))
        result = c.start()
        assert result["status"] == "error"
        assert result["error"] == "file_not_found"

    @patch.object(PasswordCracker, "run_hashcat")
    @patch.object(PasswordCracker, "_select_tool", return_value="hashcat")
    def test_start_uses_hashcat_for_22000(self, mock_select, mock_run_hashcat, tmp_path):
        f = tmp_path / "cap.22000"
        f.write_text("hash")
        c = PasswordCracker(capture_file=str(f), output_dir=str(tmp_path / "out"))
        mock_run_hashcat.return_value = {"cracked": True, "password": "pw", "tool": "hashcat"}

        result = c.start()
        mock_run_hashcat.assert_called_once_with(str(f))
        assert result["cracked"] is True
        assert result["password"] == "pw"

    @patch.object(PasswordCracker, "run_aircrack")
    @patch.object(PasswordCracker, "_select_tool", return_value="aircrack")
    def test_start_uses_aircrack_for_pcap(self, mock_select, mock_run_aircrack, capture_file, tmp_path):
        c = PasswordCracker(capture_file=capture_file, output_dir=str(tmp_path / "out"))
        mock_run_aircrack.return_value = {"cracked": False, "password": None, "tool": "aircrack"}

        result = c.start()
        mock_run_aircrack.assert_called_once()
        assert result["cracked"] is False

    @patch.object(PasswordCracker, "run_hashcat")
    @patch.object(PasswordCracker, "convert_to_hashcat")
    @patch.object(PasswordCracker, "_select_tool", return_value="hashcat")
    def test_start_converts_pcap_before_hashcat(self, mock_select, mock_convert, mock_run_hashcat,
                                                 capture_file, tmp_path):
        converted = str(tmp_path / "converted.22000")
        mock_convert.return_value = converted
        mock_run_hashcat.return_value = {"cracked": False, "password": None, "tool": "hashcat"}

        c = PasswordCracker(capture_file=capture_file, output_dir=str(tmp_path / "out"))
        c.start()
        mock_convert.assert_called_once_with(capture_file)
        mock_run_hashcat.assert_called_once_with(converted)

    def test_saves_results_json(self, tmp_path, capture_file):
        out_dir = tmp_path / "out"
        c = PasswordCracker(capture_file=capture_file, output_dir=str(out_dir), tool="aircrack")
        with patch.object(PasswordCracker, "run_aircrack",
                           return_value={"cracked": True, "password": "pw", "tool": "aircrack"}):
            c.start()

        json_files = list(out_dir.glob("crack_result_*.json"))
        assert len(json_files) == 1
        data = json.loads(json_files[0].read_text())
        assert data["cracked"] is True
        assert data["password"] == "pw"
        assert data["input_file"] == capture_file


class TestCLI:
    def test_cli_invalid_bssid_exits(self, capture_file, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", [
            "password_crack.py", capture_file, "-b", "not-a-mac",
        ])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    @patch("shutil.which", return_value=None)
    def test_cli_no_tools_exits(self, mock_which, capture_file, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["password_crack.py", capture_file])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    @patch.object(PasswordCracker, "start")
    @patch.object(PasswordCracker, "check_tools")
    def test_cli_success_exit_code(self, mock_check_tools, mock_start, capture_file, monkeypatch):
        mock_check_tools.return_value = {"hashcat": True, "aircrack": False,
                                          "hcxpcapngtool": False, "cap2hccapx": False}
        mock_start.return_value = {"status": "cracked", "tool": "hashcat",
                                    "cracked": True, "password": "pw"}
        monkeypatch.setattr(sys, "argv", ["password_crack.py", capture_file])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    @patch.object(PasswordCracker, "start")
    @patch.object(PasswordCracker, "check_tools")
    def test_cli_failure_exit_code(self, mock_check_tools, mock_start, capture_file, monkeypatch):
        mock_check_tools.return_value = {"hashcat": True, "aircrack": False,
                                          "hcxpcapngtool": False, "cap2hccapx": False}
        mock_start.return_value = {"status": "not_cracked", "tool": "hashcat",
                                    "cracked": False, "password": None}
        monkeypatch.setattr(sys, "argv", ["password_crack.py", capture_file])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_cli_parses_args(self, capture_file, monkeypatch):
        monkeypatch.setattr(sys, "argv", [
            "password_crack.py", capture_file,
            "-b", "AA:BB:CC:DD:EE:FF",
            "-w", "/tmp/words.txt",
            "--tool", "hashcat",
            "--rules", "best64.rule",
            "--no-gpu",
            "-t", "120",
            "-o", "out_dir",
        ])
        with patch.object(PasswordCracker, "check_tools",
                           return_value={"hashcat": True, "aircrack": False,
                                         "hcxpcapngtool": False, "cap2hccapx": False}), \
             patch.object(PasswordCracker, "start",
                          return_value={"status": "not_cracked", "cracked": False,
                                        "tool": "hashcat", "password": None}) as mock_start:
            with pytest.raises(SystemExit):
                main()
            # verify construction happened with parsed args by checking start was called
            mock_start.assert_called_once()
