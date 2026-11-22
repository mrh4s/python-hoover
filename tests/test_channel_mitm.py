"""Tests for channel_mitm.py -- channel-based WiFi MitM positioning module."""

import json
import os
import sys
import threading
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing the module under test
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.utils", MagicMock())

# Mock multi_adapter and deauth so channel_mitm's imports succeed without
# requiring their real implementations (and so we can control behavior).
_mock_multi_adapter = MagicMock()
_mock_deauth_module = MagicMock()
sys.modules.setdefault("multi_adapter", _mock_multi_adapter)
sys.modules.setdefault("deauth", _mock_deauth_module)

from channel_mitm import (  # noqa: E402
    ChannelMitM,
    CHANNELS_2GHZ,
    CHANNELS_5GHZ,
    main,
)

from scapy.layers.dot11 import Dot11, RadioTap  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mitm(tmp_path):
    """Create a ChannelMitM instance with safe defaults for testing."""
    return ChannelMitM(
        rogue_interface="wlan1",
        monitor_interface="wlan0mon",
        target_bssid="aa:bb:cc:dd:ee:ff",
        target_channel=6,
        target_client="11:22:33:44:55:66",
        ssid="TargetAP",
        timeout=60,
        output_dir=str(tmp_path / "captures"),
    )


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_defaults(self, tmp_path):
        m = ChannelMitM(
            rogue_interface="wlan1",
            monitor_interface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:ff",
            target_channel=6,
            output_dir=str(tmp_path / "out"),
        )
        assert m.rogue_interface == "wlan1"
        assert m.monitor_interface == "wlan0mon"
        assert m.target_bssid == "aa:bb:cc:dd:ee:ff"
        assert m.target_channel == 6
        assert m.target_client is None
        assert m.ssid == "Rogue-AP"
        assert m.timeout == 600
        assert m.forward_frames is True
        assert m.rogue_channel is not None

    def test_init_explicit_rogue_channel(self, tmp_path):
        m = ChannelMitM(
            rogue_interface="wlan1",
            monitor_interface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:ff",
            target_channel=6,
            rogue_channel=44,
            output_dir=str(tmp_path / "out"),
        )
        assert m.rogue_channel == 44

    def test_init_custom_ssid_and_client(self, mitm):
        assert mitm.ssid == "TargetAP"
        assert mitm.target_client == "11:22:33:44:55:66"

    def test_init_forward_frames_disabled(self, tmp_path):
        m = ChannelMitM(
            rogue_interface="wlan1",
            monitor_interface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:ff",
            target_channel=6,
            output_dir=str(tmp_path / "out"),
            forward_frames=False,
        )
        assert m.forward_frames is False

    def test_init_state_containers(self, mitm):
        assert mitm.connected_clients == set()
        assert mitm.relayed_frames == []
        assert mitm.results == {}
        assert isinstance(mitm._lock, type(threading.Lock()))
        assert isinstance(mitm._stop_event, threading.Event)


# ---------------------------------------------------------------------------
# Rogue channel selection
# ---------------------------------------------------------------------------

class TestSelectRogueChannel:
    def test_2ghz_target_selects_5ghz(self, mitm):
        channel = mitm._select_rogue_channel(6)
        assert channel in CHANNELS_5GHZ

    def test_5ghz_target_selects_2ghz(self, mitm):
        channel = mitm._select_rogue_channel(44)
        assert channel in CHANNELS_2GHZ

    def test_unknown_band_falls_back(self, mitm):
        channel = mitm._select_rogue_channel(999)
        assert channel in (6, 11)

    def test_selected_channel_differs_from_target(self, mitm):
        channel = mitm._select_rogue_channel(6)
        assert channel != 6


# ---------------------------------------------------------------------------
# hostapd config generation
# ---------------------------------------------------------------------------

class TestGenerateHostapdConf:
    def test_contains_matching_bssid(self, mitm):
        conf = mitm._generate_hostapd_conf(
            ssid="TargetAP", interface="wlan1", channel=44,
            bssid="aa:bb:cc:dd:ee:ff",
        )
        assert "bssid=aa:bb:cc:dd:ee:ff" in conf

    def test_contains_ssid_and_interface(self, mitm):
        conf = mitm._generate_hostapd_conf(
            ssid="TargetAP", interface="wlan1", channel=6,
            bssid="aa:bb:cc:dd:ee:ff",
        )
        assert "ssid=TargetAP" in conf
        assert "interface=wlan1" in conf
        assert "channel=6" in conf

    def test_open_auth_no_encryption(self, mitm):
        conf = mitm._generate_hostapd_conf(
            ssid="TargetAP", interface="wlan1", channel=6,
            bssid="aa:bb:cc:dd:ee:ff",
        )
        assert "auth_algs=1" in conf
        assert "wpa=" not in conf

    def test_5ghz_channel_uses_hw_mode_a(self, mitm):
        conf = mitm._generate_hostapd_conf(
            ssid="TargetAP", interface="wlan1", channel=44,
            bssid="aa:bb:cc:dd:ee:ff",
        )
        assert "hw_mode=a" in conf

    def test_2ghz_channel_uses_hw_mode_g(self, mitm):
        conf = mitm._generate_hostapd_conf(
            ssid="TargetAP", interface="wlan1", channel=6,
            bssid="aa:bb:cc:dd:ee:ff",
        )
        assert "hw_mode=g" in conf


# ---------------------------------------------------------------------------
# Rogue AP setup
# ---------------------------------------------------------------------------

class TestSetupRogueAp:
    @patch("channel_mitm.subprocess.Popen")
    def test_starts_hostapd_with_conf_path(self, mock_popen, mitm):
        mock_proc = MagicMock()
        mock_popen.return_value = mock_proc

        proc = mitm._setup_rogue_ap(
            interface="wlan1", ssid="TargetAP", channel=44,
        )

        assert proc is mock_proc
        assert mitm._hostapd_proc is mock_proc
        args, kwargs = mock_popen.call_args
        assert args[0][0] == "hostapd"
        assert mitm._hostapd_conf_path in args[0]

    @patch("channel_mitm.subprocess.Popen", side_effect=FileNotFoundError)
    def test_hostapd_missing_raises_runtime_error(self, mock_popen, mitm):
        with pytest.raises(RuntimeError):
            mitm._setup_rogue_ap(interface="wlan1", ssid="TargetAP", channel=44)


# ---------------------------------------------------------------------------
# Deauth delegation
# ---------------------------------------------------------------------------

class TestDeauthClient:
    @patch("channel_mitm.sendp")
    def test_delegates_to_deauth_attacker(self, mock_sendp, mitm):
        mock_attacker_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.create_deauth_packet.return_value = ["pkt1", "pkt2"]
        mock_instance.packets_sent = 0
        mock_attacker_cls.return_value = mock_instance

        with patch("channel_mitm.DeauthAttacker", mock_attacker_cls):
            mitm._deauth_client(
                monitor_interface="wlan0mon",
                target_bssid="aa:bb:cc:dd:ee:ff",
                client="11:22:33:44:55:66",
            )

        mock_attacker_cls.assert_called_once_with(
            interface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:ff",
            target_client="11:22:33:44:55:66",
            channel=mitm.target_channel,
        )
        mock_instance.set_channel.assert_called_once()
        mock_sendp.assert_called_once()

    @patch("channel_mitm.sendp", side_effect=Exception("inject failed"))
    def test_deauth_send_failure_is_handled(self, mock_sendp, mitm):
        mock_attacker_cls = MagicMock()
        mock_instance = MagicMock()
        mock_instance.create_deauth_packet.return_value = ["pkt1"]
        mock_instance.packets_sent = 0
        mock_attacker_cls.return_value = mock_instance

        with patch("channel_mitm.DeauthAttacker", mock_attacker_cls):
            # Should not raise even though sendp fails.
            mitm._deauth_client(
                monitor_interface="wlan0mon",
                target_bssid="aa:bb:cc:dd:ee:ff",
                client=None,
            )


# ---------------------------------------------------------------------------
# Client connection detection
# ---------------------------------------------------------------------------

class TestDetectClientConnected:
    def test_no_clients_returns_false(self, mitm):
        assert mitm._detect_client_connected() is False

    def test_target_client_connected_returns_true(self, mitm):
        mitm.connected_clients.add("11:22:33:44:55:66")
        assert mitm._detect_client_connected() is True

    def test_target_client_case_insensitive(self, mitm):
        mitm.connected_clients.add("11:22:33:44:55:66".upper())
        assert mitm._detect_client_connected() is True

    def test_other_client_without_target_set(self, tmp_path):
        m = ChannelMitM(
            rogue_interface="wlan1",
            monitor_interface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:ff",
            target_channel=6,
            target_client=None,
            output_dir=str(tmp_path / "out"),
        )
        m.connected_clients.add("ff:ee:dd:cc:bb:aa")
        assert m._detect_client_connected() is True

    def test_different_client_not_target(self, mitm):
        mitm.connected_clients.add("ff:ee:dd:cc:bb:aa")
        assert mitm._detect_client_connected() is False


# ---------------------------------------------------------------------------
# Frame relay handler
# ---------------------------------------------------------------------------

class TestRelayHandler:
    @patch("channel_mitm.sendp")
    def test_relays_frame_to_destination_interface(self, mock_sendp, mitm):
        packet = MagicMock()
        packet.haslayer.return_value = False

        mitm._relay_handler(packet, "wlan1", "wlan0mon")

        mock_sendp.assert_called_once()
        _, kwargs = mock_sendp.call_args
        assert kwargs.get("iface") == "wlan0mon"

    @patch("channel_mitm.sendp")
    def test_stop_event_prevents_relay(self, mock_sendp, mitm):
        mitm._stop_event.set()
        packet = MagicMock()

        mitm._relay_handler(packet, "wlan1", "wlan0mon")

        mock_sendp.assert_not_called()

    @patch("channel_mitm.sendp", side_effect=Exception("tx error"))
    def test_relay_error_is_swallowed(self, mock_sendp, mitm):
        packet = MagicMock()
        packet.haslayer.return_value = False
        # Should not raise.
        mitm._relay_handler(packet, "wlan1", "wlan0mon")

    @patch("channel_mitm.sendp")
    def test_relay_records_frame(self, mock_sendp, mitm):
        packet = MagicMock()
        packet.haslayer.return_value = False

        mitm._relay_handler(packet, "wlan1", "wlan0mon")

        assert len(mitm.relayed_frames) == 1
        assert mitm.relayed_frames[0]["from"] == "wlan1"
        assert mitm.relayed_frames[0]["to"] == "wlan0mon"


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

class TestCleanup:
    def test_terminates_hostapd_process(self, mitm):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = None
        mitm._hostapd_proc = mock_proc

        mitm._cleanup()

        mock_proc.terminate.assert_called_once()
        assert mitm._hostapd_proc is None

    def test_removes_temp_conf_file(self, mitm, tmp_path):
        conf_path = tmp_path / "rogue.conf"
        conf_path.write_text("test")
        mitm._hostapd_conf_path = str(conf_path)

        mitm._cleanup()

        assert not conf_path.exists()
        assert mitm._hostapd_conf_path is None

    def test_cleanup_handles_missing_process_gracefully(self, mitm):
        mitm._hostapd_proc = None
        mitm._hostapd_conf_path = None
        # Should not raise.
        mitm._cleanup()


# ---------------------------------------------------------------------------
# save_results / get_status
# ---------------------------------------------------------------------------

class TestSaveResults:
    def test_returns_none_without_results(self, mitm):
        assert mitm.save_results() is None

    def test_saves_json_file(self, mitm):
        mitm.results = {"target_bssid": "aa:bb:cc:dd:ee:ff", "rogue_channel": 44}
        mitm.connected_clients.add("11:22:33:44:55:66")

        path = mitm.save_results()

        assert path is not None
        assert os.path.exists(path)
        with open(path) as f:
            data = json.load(f)
        assert data["target_bssid"] == "aa:bb:cc:dd:ee:ff"
        assert "11:22:33:44:55:66" in data["connected_clients"]


class TestGetStatus:
    def test_status_fields(self, mitm):
        status = mitm.get_status()
        assert status["rogue_interface"] == "wlan1"
        assert status["monitor_interface"] == "wlan0mon"
        assert status["target_bssid"] == "aa:bb:cc:dd:ee:ff"
        assert status["running"] is False
        assert status["connected_clients"] == 0
        assert status["relayed_frames"] == 0

    def test_hostapd_running_true_when_process_alive(self, mitm):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None
        mitm._hostapd_proc = mock_proc

        status = mitm.get_status()
        assert status["hostapd_running"] is True

    def test_hostapd_running_false_when_process_exited(self, mitm):
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 1
        mitm._hostapd_proc = mock_proc

        status = mitm.get_status()
        assert status["hostapd_running"] is False


# ---------------------------------------------------------------------------
# stop()
# ---------------------------------------------------------------------------

class TestStop:
    def test_sets_stop_event_and_cleans_up(self, mitm):
        mock_proc = MagicMock()
        mock_proc.wait.return_value = None
        mitm._hostapd_proc = mock_proc

        mitm.stop()

        assert mitm._stop_event.is_set()
        assert mitm._running is False
        assert mitm._hostapd_proc is None

    def test_stop_joins_alive_threads(self, mitm):
        thread = MagicMock()
        thread.is_alive.return_value = True
        mitm._rogue_sniff_thread = thread
        mitm._monitor_sniff_thread = None

        mitm.stop()

        thread.join.assert_called_once()


# ---------------------------------------------------------------------------
# start() -- validation and orchestration
# ---------------------------------------------------------------------------

class TestStart:
    def test_start_rejects_invalid_interface(self, tmp_path):
        m = ChannelMitM(
            rogue_interface="bad iface!",
            monitor_interface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:ff",
            target_channel=6,
            output_dir=str(tmp_path / "out"),
        )
        with pytest.raises(ValueError):
            m.start()

    def test_start_rejects_invalid_bssid(self, tmp_path):
        m = ChannelMitM(
            rogue_interface="wlan1",
            monitor_interface="wlan0mon",
            target_bssid="not-a-mac",
            target_channel=6,
            output_dir=str(tmp_path / "out"),
        )
        with pytest.raises(ValueError):
            m.start()

    def test_start_rejects_invalid_client(self, tmp_path):
        m = ChannelMitM(
            rogue_interface="wlan1",
            monitor_interface="wlan0mon",
            target_bssid="aa:bb:cc:dd:ee:ff",
            target_channel=6,
            target_client="not-a-mac",
            output_dir=str(tmp_path / "out"),
        )
        with pytest.raises(ValueError):
            m.start()

    @patch("channel_mitm.time.sleep")
    @patch.object(ChannelMitM, "_start_frame_relay")
    @patch.object(ChannelMitM, "_deauth_client")
    @patch.object(ChannelMitM, "_setup_rogue_ap")
    def test_start_runs_full_sequence(self, mock_setup, mock_deauth,
                                       mock_relay, mock_sleep, mitm):
        mock_setup.return_value = MagicMock()
        mitm._hostapd_proc = MagicMock()

        results = mitm.start()

        mock_setup.assert_called_once()
        mock_deauth.assert_called_once()
        mock_relay.assert_called_once()
        assert results["target_bssid"] == "aa:bb:cc:dd:ee:ff"
        assert "end_time" in results

    @patch("channel_mitm.time.sleep")
    @patch.object(ChannelMitM, "_deauth_client")
    @patch.object(ChannelMitM, "_setup_rogue_ap")
    def test_start_skips_relay_when_forward_disabled(
        self, mock_setup, mock_deauth, mock_sleep, mitm,
    ):
        mitm.forward_frames = False
        with patch.object(ChannelMitM, "_start_frame_relay") as mock_relay:
            mitm.start()
            mock_relay.assert_not_called()

    @patch("channel_mitm.time.sleep")
    @patch.object(ChannelMitM, "_setup_rogue_ap", side_effect=RuntimeError("no hostapd"))
    def test_start_captures_setup_error(self, mock_setup, mock_sleep, mitm):
        results = mitm.start()
        assert "error" in results
        assert mitm._running is False


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

class TestCLI:
    @patch("channel_mitm.time.sleep")
    @patch("channel_mitm.require_root")
    @patch.object(ChannelMitM, "save_results", return_value="/tmp/out.json")
    @patch.object(ChannelMitM, "stop")
    @patch.object(ChannelMitM, "start", return_value={"rogue_channel": 44, "client_connected": True})
    def test_cli_valid_args(self, mock_start, mock_stop, mock_save,
                             mock_require_root, mock_sleep):
        test_args = [
            "channel_mitm.py",
            "--rogue-iface", "wlan1",
            "--monitor-iface", "wlan0mon",
            "-b", "aa:bb:cc:dd:ee:ff",
            "-c", "6",
            "--client", "11:22:33:44:55:66",
            "--ssid", "TargetAP",
        ]
        with patch.object(sys, "argv", test_args):
            main()

        mock_start.assert_called_once()
        mock_stop.assert_called_once()

    @patch("channel_mitm.require_root")
    def test_cli_rejects_invalid_bssid(self, mock_require_root, capsys):
        test_args = [
            "channel_mitm.py",
            "--rogue-iface", "wlan1",
            "--monitor-iface", "wlan0mon",
            "-b", "not-a-mac",
            "-c", "6",
        ]
        with patch.object(sys, "argv", test_args):
            with pytest.raises(SystemExit):
                main()

    @patch("channel_mitm.require_root")
    def test_cli_rejects_invalid_interface(self, mock_require_root):
        test_args = [
            "channel_mitm.py",
            "--rogue-iface", "bad iface!",
            "--monitor-iface", "wlan0mon",
            "-b", "aa:bb:cc:dd:ee:ff",
            "-c", "6",
        ]
        with patch.object(sys, "argv", test_args):
            with pytest.raises(SystemExit):
                main()

    @patch("channel_mitm.require_root")
    def test_cli_rejects_invalid_client(self, mock_require_root):
        test_args = [
            "channel_mitm.py",
            "--rogue-iface", "wlan1",
            "--monitor-iface", "wlan0mon",
            "-b", "aa:bb:cc:dd:ee:ff",
            "-c", "6",
            "--client", "garbage",
        ]
        with patch.object(sys, "argv", test_args):
            with pytest.raises(SystemExit):
                main()

    @patch("channel_mitm.time.sleep")
    @patch("channel_mitm.require_root")
    @patch.object(ChannelMitM, "save_results", return_value=None)
    @patch.object(ChannelMitM, "stop")
    @patch.object(ChannelMitM, "start", return_value={"rogue_channel": 149, "client_connected": False})
    def test_cli_no_forward_flag(self, mock_start, mock_stop, mock_save,
                                  mock_require_root, mock_sleep):
        test_args = [
            "channel_mitm.py",
            "--rogue-iface", "wlan1",
            "--monitor-iface", "wlan0mon",
            "-b", "aa:bb:cc:dd:ee:ff",
            "-c", "6",
            "--no-forward",
        ]
        with patch.object(sys, "argv", test_args):
            main()
        mock_start.assert_called_once()
