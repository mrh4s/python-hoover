"""Tests for eap_attack.py — WPA-Enterprise EAP Attack module."""

import json
import os
import sys
import time
from unittest.mock import MagicMock, patch, call

import pytest

# Mock scapy before importing
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.layers.eap", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

from eap_attack import (  # noqa: E402
    EAPAttack,
    EAP_TYPE_IDENTITY,
    EAP_TYPE_MSCHAPV2,
    EAP_TYPE_MD5,
    EAP_CODE_RESPONSE,
    SUPPORTED_EAP_METHODS,
    main,
)

# Import mocked classes as production code sees them
from scapy.layers.dot11 import Dot11  # noqa: E402
from scapy.layers.eap import EAP  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def attack(mock_interface, tmp_path):
    return EAPAttack(
        interface=mock_interface,
        ssid="TestEnterprise",
        channel=6,
        output_dir=str(tmp_path / "captures"),
        timeout=300,
        eap_method="peap",
    )


def _make_eap_packet(eap_code, eap_type, eap_id, identity=None,
                     src_mac="aa:bb:cc:dd:ee:ff", raw_bytes=b""):
    """Create a mock EAP packet with the given parameters."""
    pkt = MagicMock()

    eap_layer = MagicMock()
    eap_layer.code = eap_code
    eap_layer.type = eap_type
    eap_layer.id = eap_id
    eap_layer.identity = identity
    eap_layer.__bytes__ = lambda self: raw_bytes

    dot11_layer = MagicMock()
    dot11_layer.addr2 = src_mac

    layers_present = {EAP, Dot11}
    pkt.haslayer = lambda cls: cls in layers_present

    def getitem(self, cls):
        if cls is EAP:
            return eap_layer
        if cls is Dot11:
            return dot11_layer
        return MagicMock()
    pkt.__getitem__ = getitem

    return pkt


@pytest.fixture
def mock_eap_identity_packet():
    """Create a mock packet with EAP Identity Response."""
    return _make_eap_packet(
        eap_code=EAP_CODE_RESPONSE,
        eap_type=EAP_TYPE_IDENTITY,
        eap_id=1,
        identity=b"testuser@corp.example.com",
        src_mac="aa:bb:cc:dd:ee:ff",
    )


@pytest.fixture
def mock_mschapv2_packet():
    """Create a mock packet with MSCHAPv2 Response."""
    return _make_eap_packet(
        eap_code=EAP_CODE_RESPONSE,
        eap_type=EAP_TYPE_MSCHAPV2,
        eap_id=2,
        src_mac="11:22:33:44:55:66",
        raw_bytes=b"\xde\xad\xbe\xef\x01\x02",
    )


@pytest.fixture
def mock_md5_packet():
    """Create a mock packet with EAP-MD5 Response."""
    return _make_eap_packet(
        eap_code=EAP_CODE_RESPONSE,
        eap_type=EAP_TYPE_MD5,
        eap_id=3,
        src_mac="aa:11:bb:22:cc:33",
        raw_bytes=b"\xab\xcd",
    )


@pytest.fixture
def mock_non_eap_packet():
    """Create a mock packet without EAP layer."""
    pkt = MagicMock()
    pkt.haslayer = lambda cls: False
    return pkt


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEAPAttackInit:
    def test_defaults(self, mock_interface):
        a = EAPAttack(interface=mock_interface, ssid="TestNet")
        assert a.interface == mock_interface
        assert a.ssid == "TestNet"
        assert a.channel == 6
        assert a.output_dir == "captures"
        assert a.timeout == 300
        assert a.eap_method == "peap"
        assert a.captured_credentials == []
        assert a._running is False
        assert a._hostapd_proc is None

    def test_custom_params(self, mock_interface):
        a = EAPAttack(
            interface=mock_interface,
            ssid="Corp",
            channel=11,
            output_dir="/tmp/test_caps",
            timeout=600,
            eap_method="ttls",
        )
        assert a.ssid == "Corp"
        assert a.channel == 11
        assert a.output_dir == "/tmp/test_caps"
        assert a.timeout == 600
        assert a.eap_method == "ttls"

    def test_eap_method_lowercase(self, mock_interface):
        a = EAPAttack(interface=mock_interface, ssid="Net", eap_method="PEAP")
        assert a.eap_method == "peap"


class TestHostapdConfig:
    def test_config_contains_eap_settings(self, attack):
        config = attack._generate_hostapd_config()
        assert "ieee8021x=1" in config
        assert "wpa_key_mgmt=WPA-EAP" in config
        assert "eap_server=1" in config
        assert "wpa=2" in config
        assert "wpa_pairwise=CCMP" in config

    def test_config_contains_interface_and_ssid(self, attack):
        config = attack._generate_hostapd_config()
        assert f"interface={attack.interface}" in config
        assert f"ssid={attack.ssid}" in config
        assert f"channel={attack.channel}" in config

    def test_config_has_cert_placeholders(self, attack):
        config = attack._generate_hostapd_config()
        assert "eap_user_file=" in config
        assert "ca_cert=" in config
        assert "server_cert=" in config
        assert "private_key=" in config


class TestEAPUserFile:
    def test_peap_user_file(self, mock_interface):
        a = EAPAttack(interface=mock_interface, ssid="Net", eap_method="peap")
        content = a._generate_eap_user_file()
        assert "PEAP" in content
        assert "MSCHAPV2" in content
        assert '"t"' in content

    def test_ttls_user_file(self, mock_interface):
        a = EAPAttack(interface=mock_interface, ssid="Net", eap_method="ttls")
        content = a._generate_eap_user_file()
        assert "TTLS" in content
        assert "MSCHAPV2" in content

    def test_md5_user_file(self, mock_interface):
        a = EAPAttack(interface=mock_interface, ssid="Net", eap_method="md5")
        content = a._generate_eap_user_file()
        assert "MD5" in content
        # MD5 mode should not include PEAP as primary
        lines = content.strip().split("\n")
        method_line = [l for l in lines if not l.startswith("#") and "*" in l]
        assert len(method_line) == 1
        assert method_line[0].strip() == "* MD5"

    def test_user_file_has_header(self, attack):
        content = attack._generate_eap_user_file()
        assert content.startswith("#")

    def test_unknown_method_falls_back_to_peap(self, mock_interface):
        a = EAPAttack(interface=mock_interface, ssid="Net", eap_method="unknown")
        content = a._generate_eap_user_file()
        assert "PEAP" in content


class TestPacketHandler:
    def test_identity_response_captured(self, attack, mock_eap_identity_packet):
        attack.packet_handler(mock_eap_identity_packet)
        assert len(attack.captured_credentials) == 1
        cred = attack.captured_credentials[0]
        assert cred["type"] == "eap_identity"
        assert cred["identity"] == "testuser@corp.example.com"
        assert cred["src_mac"] == "aa:bb:cc:dd:ee:ff"
        assert cred["eap_id"] == 1

    def test_mschapv2_response_captured(self, attack, mock_mschapv2_packet):
        attack.packet_handler(mock_mschapv2_packet)
        assert len(attack.captured_credentials) == 1
        cred = attack.captured_credentials[0]
        assert cred["type"] == "mschapv2_response"
        assert cred["src_mac"] == "11:22:33:44:55:66"
        assert cred["eap_id"] == 2

    def test_md5_response_captured(self, attack, mock_md5_packet):
        attack.packet_handler(mock_md5_packet)
        assert len(attack.captured_credentials) == 1
        cred = attack.captured_credentials[0]
        assert cred["type"] == "md5_challenge_response"
        assert cred["src_mac"] == "aa:11:bb:22:cc:33"

    def test_non_eap_packet_ignored(self, attack, mock_non_eap_packet):
        attack.packet_handler(mock_non_eap_packet)
        assert len(attack.captured_credentials) == 0

    def test_multiple_credentials(self, attack, mock_eap_identity_packet, mock_mschapv2_packet):
        attack.packet_handler(mock_eap_identity_packet)
        attack.packet_handler(mock_mschapv2_packet)
        assert len(attack.captured_credentials) == 2

    def test_credential_has_timestamp(self, attack, mock_eap_identity_packet):
        attack.packet_handler(mock_eap_identity_packet)
        cred = attack.captured_credentials[0]
        assert "timestamp" in cred
        # Check timestamp format
        assert len(cred["timestamp"]) == 19  # "YYYY-MM-DD HH:MM:SS"


class TestGetCapturedCredentials:
    def test_returns_copy(self, attack, mock_eap_identity_packet):
        attack.packet_handler(mock_eap_identity_packet)
        creds = attack.get_captured_credentials()
        assert len(creds) == 1
        # Modifying returned list shouldn't affect internal state
        creds.clear()
        assert len(attack.captured_credentials) == 1

    def test_empty_when_no_captures(self, attack):
        creds = attack.get_captured_credentials()
        assert creds == []


class TestGetStatus:
    def test_initial_status(self, attack):
        status = attack.get_status()
        assert status["running"] is False
        assert status["interface"] == attack.interface
        assert status["ssid"] == attack.ssid
        assert status["channel"] == attack.channel
        assert status["eap_method"] == "peap"
        assert status["credentials_count"] == 0
        assert status["timeout"] == 300

    def test_status_with_credentials(self, attack, mock_eap_identity_packet):
        attack.packet_handler(mock_eap_identity_packet)
        status = attack.get_status()
        assert status["credentials_count"] == 1

    def test_status_elapsed_time(self, attack):
        attack._start_time = time.time() - 10.0
        status = attack.get_status()
        assert status["elapsed_seconds"] >= 9.0


class TestStartStop:
    @patch("eap_attack.sniff")
    @patch("eap_attack.subprocess.Popen")
    @patch("eap_attack.subprocess.run")
    @patch("eap_attack.validate_interface", return_value=True)
    @patch("eap_attack.signal.signal")
    @patch("eap_attack.time.sleep")
    def test_start_configures_interface(
        self, mock_sleep, mock_signal, mock_validate, mock_run, mock_popen, mock_sniff, attack
    ):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        # Make stop_event get set quickly
        attack._stop_event = MagicMock()
        attack._stop_event.is_set.side_effect = [False, True]
        attack._stop_event.wait.return_value = None

        attack.start()

        # Verify interface config calls
        ip_calls = [c for c in mock_run.call_args_list if c[0][0][0] == "ip"]
        assert len(ip_calls) == 3  # flush, add addr, link set up

    @patch("eap_attack.sniff")
    @patch("eap_attack.subprocess.Popen")
    @patch("eap_attack.subprocess.run")
    @patch("eap_attack.validate_interface", return_value=True)
    @patch("eap_attack.signal.signal")
    @patch("eap_attack.time.sleep")
    def test_start_launches_hostapd(
        self, mock_sleep, mock_signal, mock_validate, mock_run, mock_popen, mock_sniff, attack
    ):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc

        attack._stop_event = MagicMock()
        attack._stop_event.is_set.side_effect = [False, True]
        attack._stop_event.wait.return_value = None

        attack.start()

        mock_popen.assert_called_once()
        popen_args = mock_popen.call_args[0][0]
        assert popen_args[0] == "hostapd"

    @patch("eap_attack.subprocess.Popen", side_effect=FileNotFoundError)
    @patch("eap_attack.subprocess.run")
    @patch("eap_attack.validate_interface", return_value=True)
    @patch("eap_attack.signal.signal")
    @patch("eap_attack.time.sleep")
    def test_start_exits_if_hostapd_missing(
        self, mock_sleep, mock_signal, mock_validate, mock_run, mock_popen, attack
    ):
        with pytest.raises(SystemExit):
            attack.start()

    @patch("eap_attack.validate_interface", return_value=False)
    def test_start_exits_on_invalid_interface(self, mock_validate, attack):
        with pytest.raises(SystemExit):
            attack.start()

    def test_stop_terminates_hostapd(self, attack):
        mock_proc = MagicMock()
        attack._hostapd_proc = mock_proc
        attack.stop()
        mock_proc.terminate.assert_called_once()

    def test_stop_cleans_temp_files(self, attack, tmp_path):
        tmp_file = tmp_path / "test_conf"
        tmp_file.write_text("test")
        attack._temp_files.append(str(tmp_file))
        attack.stop()
        assert not tmp_file.exists()

    def test_stop_saves_credentials(self, attack, mock_eap_identity_packet, tmp_path):
        attack.output_dir = str(tmp_path / "output")
        attack.packet_handler(mock_eap_identity_packet)
        attack.stop()
        # Check that a JSON file was created
        output_files = os.listdir(attack.output_dir)
        json_files = [f for f in output_files if f.endswith(".json")]
        assert len(json_files) == 1
        with open(os.path.join(attack.output_dir, json_files[0])) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["type"] == "eap_identity"

    def test_stop_no_save_when_empty(self, attack, tmp_path):
        attack.output_dir = str(tmp_path / "empty_output")
        attack.stop()
        assert not os.path.exists(attack.output_dir)


class TestSupportedMethods:
    def test_supported_methods_tuple(self):
        assert "peap" in SUPPORTED_EAP_METHODS
        assert "ttls" in SUPPORTED_EAP_METHODS
        assert "md5" in SUPPORTED_EAP_METHODS


class TestCLIParsing:
    @patch("eap_attack.require_root")
    @patch("eap_attack.EAPAttack")
    def test_required_args(self, mock_cls, mock_root):
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance

        with patch("sys.argv", ["eap_attack", "-i", "wlan0", "-s", "TestNet"]):
            main()

        mock_root.assert_called_once()
        mock_cls.assert_called_once_with(
            interface="wlan0",
            ssid="TestNet",
            channel=6,
            output_dir="captures",
            timeout=300,
            eap_method="peap",
        )
        mock_instance.start.assert_called_once()

    @patch("eap_attack.require_root")
    @patch("eap_attack.EAPAttack")
    def test_all_args(self, mock_cls, mock_root):
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance

        with patch("sys.argv", [
            "eap_attack", "-i", "wlan1", "-s", "CorpWiFi",
            "-ch", "11", "-m", "ttls", "-o", "/tmp/out", "-t", "600",
        ]):
            main()

        mock_cls.assert_called_once_with(
            interface="wlan1",
            ssid="CorpWiFi",
            channel=11,
            output_dir="/tmp/out",
            timeout=600,
            eap_method="ttls",
        )

    @patch("eap_attack.require_root")
    @patch("eap_attack.EAPAttack")
    def test_verbose_flag(self, mock_cls, mock_root):
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance

        with patch("sys.argv", [
            "eap_attack", "-i", "wlan0", "-s", "Net", "-v",
        ]):
            main()

        mock_instance.start.assert_called_once()

    def test_missing_required_args_exits(self):
        with patch("sys.argv", ["eap_attack"]):
            with pytest.raises(SystemExit):
                main()

    def test_invalid_method_exits(self):
        with patch("sys.argv", [
            "eap_attack", "-i", "wlan0", "-s", "Net", "-m", "invalid",
        ]):
            with pytest.raises(SystemExit):
                main()
