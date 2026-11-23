"""Tests for multi_adapter.py — Multi-Adapter Management module."""

import json
from unittest.mock import MagicMock, call, patch

import pytest

from multi_adapter import (  # noqa: E402
    MultiAdapterManager,
    _parse_adapters_arg,
    main,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def manager():
    return MultiAdapterManager(verbose=False)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMultiAdapterManager:
    def test_init_defaults(self, manager):
        """Default constructor has an empty adapter registry."""
        assert manager.adapters == {}

    def test_add_adapter(self, manager, mock_interface):
        """Adding an adapter registers it in the adapters dict."""
        manager.add_adapter(mock_interface, "monitor", channel=6)
        assert mock_interface in manager.adapters
        assert manager.adapters[mock_interface]["role"] == "monitor"
        assert manager.adapters[mock_interface]["channel"] == 6

    def test_add_adapter_invalid_role(self, manager, mock_interface):
        """An unrecognized role raises ValueError."""
        with pytest.raises(ValueError):
            manager.add_adapter(mock_interface, "bogus-role")

    def test_remove_adapter(self, manager, mock_interface):
        """Removing a previously added adapter removes it from the registry."""
        manager.add_adapter(mock_interface, "monitor")
        assert mock_interface in manager.adapters
        manager.remove_adapter(mock_interface)
        assert mock_interface not in manager.adapters

    def test_discover_adapters_mocked(self, manager, tmp_path):
        """discover_adapters finds interfaces from mocked /sys/class/net globs."""
        def fake_glob(pattern):
            if pattern == "/sys/class/net/*/wireless":
                return ["/sys/class/net/wlan0/wireless"]
            if pattern == "/sys/class/net/*/phy80211":
                return ["/sys/class/net/wlan0/phy80211"]
            return []

        with patch("multi_adapter.glob.glob", side_effect=fake_glob), \
                patch.object(manager, "_get_phy_name", return_value="phy0"), \
                patch.object(manager, "_get_driver", return_value="ath9k"), \
                patch.object(manager, "_get_mac", return_value="AA:BB:CC:DD:EE:FF"), \
                patch.object(manager, "_get_phy_modes", return_value=["managed", "monitor"]):
            discovered = manager.discover_adapters()

        assert len(discovered) == 1
        assert discovered[0]["interface"] == "wlan0"
        assert discovered[0]["phy"] == "phy0"
        assert discovered[0]["driver"] == "ath9k"
        assert discovered[0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert "monitor" in discovered[0]["modes"]

    def test_set_monitor_mode(self, manager, mock_interface):
        """set_monitor_mode runs the expected ip/iw command sequence."""
        manager.add_adapter(mock_interface, "monitor")
        with patch("multi_adapter.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = manager.set_monitor_mode(mock_interface)

        assert result is True
        expected_calls = [
            call(["ip", "link", "set", mock_interface, "down"],
                 capture_output=True, text=True, timeout=5, check=True),
            call(["iw", "dev", mock_interface, "set", "type", "monitor"],
                 capture_output=True, text=True, timeout=5, check=True),
            call(["ip", "link", "set", mock_interface, "up"],
                 capture_output=True, text=True, timeout=5, check=True),
        ]
        assert mock_run.call_args_list == expected_calls
        assert manager.adapters[mock_interface]["current_mode"] == "monitor"

    def test_set_managed_mode(self, manager, mock_interface):
        """set_managed_mode runs the expected ip/iw command sequence."""
        manager.add_adapter(mock_interface, "monitor")
        with patch("multi_adapter.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = manager.set_managed_mode(mock_interface)

        assert result is True
        expected_calls = [
            call(["ip", "link", "set", mock_interface, "down"],
                 capture_output=True, text=True, timeout=5, check=True),
            call(["iw", "dev", mock_interface, "set", "type", "managed"],
                 capture_output=True, text=True, timeout=5, check=True),
            call(["ip", "link", "set", mock_interface, "up"],
                 capture_output=True, text=True, timeout=5, check=True),
        ]
        assert mock_run.call_args_list == expected_calls
        assert manager.adapters[mock_interface]["current_mode"] == "managed"

    def test_get_adapter_by_role(self, manager):
        """get_adapter returns the adapter dict matching a given role."""
        manager.add_adapter("wlan0", "monitor")
        manager.add_adapter("wlan1", "inject")

        monitor_adapter = manager.get_adapter("monitor")
        inject_adapter = manager.get_adapter("inject")

        assert monitor_adapter["interface"] == "wlan0"
        assert inject_adapter["interface"] == "wlan1"

    def test_get_monitor_adapter(self, manager):
        """get_monitor_adapter returns the interface name of the monitor-role adapter."""
        manager.add_adapter("wlan0", "monitor")
        manager.add_adapter("wlan1", "inject")

        assert manager.get_monitor_adapter() == "wlan0"
        assert manager.get_inject_adapter() == "wlan1"

    def test_validate_all_all_valid(self, manager):
        """validate_all returns True for every adapter when check_monitor_mode succeeds."""
        manager.add_adapter("wlan0", "monitor")
        manager.add_adapter("wlan1", "ap")

        with patch("multi_adapter.check_monitor_mode", return_value=True):
            result = manager.validate_all()

        assert result == {"wlan0": True, "wlan1": True}

    def test_validate_all_one_invalid(self, manager):
        """validate_all flags an adapter whose mode check fails."""
        manager.add_adapter("wlan0", "monitor")
        manager.add_adapter("wlan1", "scan")

        def fake_check(interface):
            return interface != "wlan1"

        with patch("multi_adapter.check_monitor_mode", side_effect=fake_check):
            result = manager.validate_all()

        assert result["wlan0"] is True
        assert result["wlan1"] is False

    def test_cleanup_restores_managed(self, manager):
        """cleanup() calls set_managed_mode for every registered adapter."""
        manager.add_adapter("wlan0", "monitor")
        manager.add_adapter("wlan1", "inject")

        with patch.object(manager, "set_managed_mode") as mock_set_managed:
            manager.cleanup()

        mock_set_managed.assert_has_calls(
            [call("wlan0"), call("wlan1")], any_order=True
        )
        assert mock_set_managed.call_count == 2


class TestMultiAdapterCLI:
    def test_cli_discover_flag(self, capsys):
        """--discover lists discovered interfaces and prints them as JSON."""
        fake_discovered = [{"interface": "wlan0", "role": None}]
        with patch("multi_adapter.sys.argv", ["multi_adapter.py", "--discover"]), \
                patch.object(MultiAdapterManager, "discover_adapters",
                              return_value=fake_discovered):
            main()

        captured = capsys.readouterr()
        output = json.loads(captured.out)
        assert output == fake_discovered

    def test_cli_adapters_parsing(self):
        """--adapters string is parsed into interface/role dicts."""
        parsed = _parse_adapters_arg("wlan0:monitor,wlan1:inject")
        assert parsed == [
            {"interface": "wlan0", "role": "monitor"},
            {"interface": "wlan1", "role": "inject"},
        ]
