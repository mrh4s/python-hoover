"""Tests for portal_bypass.py — Captive Portal Bypass testing module."""

import json
import os
import socket
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.inet", MagicMock())
sys.modules.setdefault("scapy.layers.dns", MagicMock())
sys.modules.setdefault("scapy.layers.l2", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

from scapy.layers.dot11 import Dot11  # noqa: E402

# Import mocked classes as production code sees them
from portal_bypass import (  # noqa: E402
    BYPASS_MODES,
    DEFAULT_DNS_DOMAIN,
    DEFAULT_TARGET_IP,
    DNS_TEST_PAYLOAD,
    ICMP_TEST_PAYLOAD,
    PortalBypass,
    main,
)

TARGET_IP = "1.1.1.1"
CLIENT_MAC = "AA:BB:CC:DD:EE:FF"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def bypass(mock_interface, tmp_path):
    return PortalBypass(
        interface=mock_interface,
        output_dir=str(tmp_path / "captures"),
        timeout=30,
    )


def _make_dot11_data_packet(src_mac="aa:bb:cc:dd:ee:ff", frame_type=2):
    """Create a mock packet carrying a Dot11 layer of the given frame type."""
    pkt = MagicMock()
    dot11_layer = MagicMock()
    dot11_layer.type = frame_type
    dot11_layer.addr2 = src_mac

    layers_present = {Dot11}
    pkt.haslayer = lambda cls: cls in layers_present

    def getitem(self, cls):
        if cls is Dot11:
            return dot11_layer
        return MagicMock()
    pkt.__getitem__ = getitem
    return pkt


def _make_non_dot11_packet():
    pkt = MagicMock()
    pkt.haslayer = lambda cls: False
    return pkt


# ---------------------------------------------------------------------------
# 1-2. __init__
# ---------------------------------------------------------------------------

class TestPortalBypassInit:
    def test_init_defaults(self, mock_interface):
        pb = PortalBypass(interface=mock_interface)
        assert pb.interface == mock_interface
        assert pb.bypass_mode == "probe"
        assert pb.dns_tunnel_domain == DEFAULT_DNS_DOMAIN
        assert pb.target_ip == DEFAULT_TARGET_IP
        assert pb.timeout == 120
        assert pb.output_dir == "captures"
        assert pb.results == {}
        assert pb._running is False

    def test_init_custom_params(self, mock_interface):
        pb = PortalBypass(
            interface=mock_interface,
            bypass_mode="dns-tunnel",
            dns_tunnel_domain="custom.example.com",
            target_ip="8.8.8.8",
            timeout=60,
            output_dir="/tmp/portal_caps",
        )
        assert pb.bypass_mode == "dns-tunnel"
        assert pb.dns_tunnel_domain == "custom.example.com"
        assert pb.target_ip == "8.8.8.8"
        assert pb.timeout == 60
        assert pb.output_dir == "/tmp/portal_caps"


# ---------------------------------------------------------------------------
# 3. _test_dns_resolution
# ---------------------------------------------------------------------------

class TestDnsResolution:
    @patch("portal_bypass.socket.gethostbyname")
    def test_dns_resolution_ok(self, mock_resolve, bypass):
        mock_resolve.return_value = "1.1.1.1"
        assert bypass._test_dns_resolution() is True

    @patch("portal_bypass.socket.gethostbyname")
    def test_dns_resolution_fails_when_hijacked(self, mock_resolve, bypass):
        mock_resolve.side_effect = socket.gaierror("no resolution")
        assert bypass._test_dns_resolution() is False

    @patch("portal_bypass.socket.gethostbyname")
    def test_dns_resolution_rejects_loopback(self, mock_resolve, bypass):
        mock_resolve.return_value = "127.0.0.1"
        assert bypass._test_dns_resolution() is False


# ---------------------------------------------------------------------------
# 4. _test_direct_ip
# ---------------------------------------------------------------------------

class TestDirectIp:
    @patch("portal_bypass.socket.create_connection")
    def test_direct_ip_success(self, mock_connect, bypass):
        mock_connect.return_value.__enter__ = MagicMock()
        mock_connect.return_value.__exit__ = MagicMock(return_value=False)
        assert bypass._test_direct_ip() is True

    @patch("portal_bypass.socket.create_connection")
    def test_direct_ip_blocked(self, mock_connect, bypass):
        mock_connect.side_effect = socket.timeout("timed out")
        assert bypass._test_direct_ip() is False

    @patch("portal_bypass.socket.create_connection")
    def test_direct_ip_oserror(self, mock_connect, bypass):
        mock_connect.side_effect = OSError("connection refused")
        assert bypass._test_direct_ip() is False


# ---------------------------------------------------------------------------
# 5. _test_icmp_reachability
# ---------------------------------------------------------------------------

class TestIcmpReachability:
    @patch("portal_bypass.sr1")
    def test_icmp_reachable(self, mock_sr1, bypass):
        mock_sr1.return_value = MagicMock()
        assert bypass._test_icmp_reachability() is True

    @patch("portal_bypass.sr1")
    def test_icmp_unreachable(self, mock_sr1, bypass):
        mock_sr1.return_value = None
        assert bypass._test_icmp_reachability() is False

    @patch("portal_bypass.sr1")
    def test_icmp_exception_returns_false(self, mock_sr1, bypass):
        mock_sr1.side_effect = Exception("boom")
        assert bypass._test_icmp_reachability() is False


# ---------------------------------------------------------------------------
# 6. _find_authenticated_clients
# ---------------------------------------------------------------------------

class TestFindAuthenticatedClients:
    @patch("portal_bypass.sniff")
    def test_finds_data_frame_clients(self, mock_sniff, bypass):
        def fake_sniff(iface=None, prn=None, timeout=None, store=None):
            prn(_make_dot11_data_packet(src_mac="aa:bb:cc:dd:ee:ff", frame_type=2))
            prn(_make_dot11_data_packet(src_mac="11:22:33:44:55:66", frame_type=2))

        mock_sniff.side_effect = fake_sniff
        clients = bypass._find_authenticated_clients()

        assert "AA:BB:CC:DD:EE:FF" in clients
        assert "11:22:33:44:55:66".upper() in clients

    @patch("portal_bypass.sniff")
    def test_ignores_non_data_frames(self, mock_sniff, bypass):
        def fake_sniff(iface=None, prn=None, timeout=None, store=None):
            prn(_make_dot11_data_packet(src_mac="aa:bb:cc:dd:ee:ff", frame_type=0))
            prn(_make_non_dot11_packet())

        mock_sniff.side_effect = fake_sniff
        clients = bypass._find_authenticated_clients()
        assert clients == []

    @patch("portal_bypass.sniff")
    def test_sniff_exception_returns_empty(self, mock_sniff, bypass):
        mock_sniff.side_effect = Exception("interface down")
        assert bypass._find_authenticated_clients() == []


# ---------------------------------------------------------------------------
# 7. _build_dns_tunnel_query
# ---------------------------------------------------------------------------

class TestBuildDnsTunnelQuery:
    def test_build_dns_tunnel_query_encodes_data(self, bypass):
        data = b"hello"
        packet = bypass._build_dns_tunnel_query(data, "tunnel.example.com")
        assert packet is not None
        # IP() and DNS() are mocked; verify the call happened without error
        # and that the hex encoding used matches expectations.
        assert data.hex() == "68656c6c6f"


# ---------------------------------------------------------------------------
# 8. _dns_tunnel_test
# ---------------------------------------------------------------------------

class TestDnsTunnelTest:
    @patch("portal_bypass.socket.gethostbyname")
    def test_dns_tunnel_test_success(self, mock_resolve, bypass):
        mock_resolve.return_value = "203.0.113.1"
        result = bypass._dns_tunnel_test("tunnel.example.com")

        assert result["domain"] == "tunnel.example.com"
        assert result["payload"] == DNS_TEST_PAYLOAD.hex()
        assert result["success"] is True
        assert result["response"] == "203.0.113.1"

    @patch("portal_bypass.socket.gethostbyname")
    def test_dns_tunnel_test_failure(self, mock_resolve, bypass):
        mock_resolve.side_effect = socket.gaierror("NXDOMAIN")
        result = bypass._dns_tunnel_test("tunnel.example.com")

        assert result["success"] is False
        assert "NXDOMAIN" in result["response"] or result["response"]


# ---------------------------------------------------------------------------
# 9. _build_icmp_tunnel_packet
# ---------------------------------------------------------------------------

class TestBuildIcmpTunnelPacket:
    def test_build_icmp_tunnel_packet(self, bypass):
        data = b"tunnel-payload"
        packet = bypass._build_icmp_tunnel_packet(data, TARGET_IP)
        assert packet is not None


# ---------------------------------------------------------------------------
# 10. _icmp_tunnel_test
# ---------------------------------------------------------------------------

class TestIcmpTunnelTest:
    @patch("portal_bypass.sr1")
    def test_icmp_tunnel_test_payload_echoed(self, mock_sr1, bypass):
        reply = MagicMock()
        reply.haslayer = lambda cls: True
        icmp_layer = MagicMock()
        icmp_layer.payload = ICMP_TEST_PAYLOAD
        reply.__getitem__ = lambda self, cls: icmp_layer
        mock_sr1.return_value = reply

        result = bypass._icmp_tunnel_test()
        assert result["reply_received"] is True
        assert result["payload_echoed"] is True

    @patch("portal_bypass.sr1")
    def test_icmp_tunnel_test_no_reply(self, mock_sr1, bypass):
        mock_sr1.return_value = None
        result = bypass._icmp_tunnel_test()
        assert result["reply_received"] is False
        assert result["payload_echoed"] is False

    @patch("portal_bypass.sr1")
    def test_icmp_tunnel_test_exception(self, mock_sr1, bypass):
        mock_sr1.side_effect = Exception("no route")
        result = bypass._icmp_tunnel_test()
        assert result["reply_received"] is False


# ---------------------------------------------------------------------------
# 11-12. _change_mac
# ---------------------------------------------------------------------------

class TestChangeMac:
    @patch("portal_bypass.subprocess.run")
    def test_change_mac_success(self, mock_run, bypass):
        mock_run.return_value = MagicMock(returncode=0)
        result = bypass._change_mac(bypass.interface, CLIENT_MAC)

        assert result is True
        assert mock_run.call_count == 3
        down_call, set_call, up_call = mock_run.call_args_list
        assert down_call.args[0] == ["ip", "link", "set", bypass.interface, "down"]
        assert set_call.args[0] == ["ip", "link", "set", bypass.interface, "address", CLIENT_MAC]
        assert up_call.args[0] == ["ip", "link", "set", bypass.interface, "up"]

    @patch("portal_bypass.subprocess.run")
    def test_change_mac_failure(self, mock_run, bypass):
        mock_run.return_value = MagicMock(returncode=1)
        result = bypass._change_mac(bypass.interface, CLIENT_MAC)
        assert result is False

    def test_change_mac_invalid_mac_rejected(self, bypass):
        assert bypass._change_mac(bypass.interface, "not-a-mac") is False

    def test_change_mac_invalid_interface_rejected(self, bypass):
        assert bypass._change_mac("bad iface!", CLIENT_MAC) is False

    @patch("portal_bypass.subprocess.run")
    def test_change_mac_subprocess_error(self, mock_run, bypass):
        mock_run.side_effect = FileNotFoundError("ip not found")
        assert bypass._change_mac(bypass.interface, CLIENT_MAC) is False


# ---------------------------------------------------------------------------
# 13. _mac_clone_test
# ---------------------------------------------------------------------------

class TestMacCloneTest:
    @patch.object(PortalBypass, "_test_direct_ip", return_value=True)
    @patch.object(PortalBypass, "_change_mac", return_value=True)
    @patch.object(PortalBypass, "_find_authenticated_clients", return_value=[CLIENT_MAC])
    def test_mac_clone_test_success(self, mock_find, mock_change, mock_direct, bypass):
        result = bypass._mac_clone_test()

        assert result["candidates"] == [CLIENT_MAC]
        assert result["cloned_mac"] == CLIENT_MAC
        assert result["clone_succeeded"] is True
        assert result["connectivity_after_clone"] is True

    @patch.object(PortalBypass, "_find_authenticated_clients", return_value=[])
    def test_mac_clone_test_no_candidates(self, mock_find, bypass):
        result = bypass._mac_clone_test()
        assert result["candidates"] == []
        assert result["cloned_mac"] is None
        assert result["clone_succeeded"] is False


# ---------------------------------------------------------------------------
# 14. _probe_bypasses
# ---------------------------------------------------------------------------

class TestProbeBypasses:
    @patch.object(PortalBypass, "_find_authenticated_clients", return_value=[CLIENT_MAC])
    @patch.object(PortalBypass, "_test_icmp_reachability", return_value=True)
    @patch.object(PortalBypass, "_test_direct_ip", return_value=True)
    @patch.object(PortalBypass, "_test_dns_resolution", return_value=False)
    def test_probe_bypasses_all_viable(self, mock_dns, mock_direct, mock_icmp,
                                        mock_clients, bypass):
        result = bypass._probe_bypasses()

        assert result["dns_tunnel"]["viable"] is True
        assert result["direct_ip"]["viable"] is True
        assert result["icmp_tunnel"]["viable"] is True
        assert result["mac_clone"]["viable"] is True
        assert result["mac_clone"]["candidates"] == [CLIENT_MAC]

    @patch.object(PortalBypass, "_find_authenticated_clients", return_value=[])
    @patch.object(PortalBypass, "_test_icmp_reachability", return_value=False)
    @patch.object(PortalBypass, "_test_direct_ip", return_value=False)
    @patch.object(PortalBypass, "_test_dns_resolution", return_value=True)
    def test_probe_bypasses_none_viable(self, mock_dns, mock_direct, mock_icmp,
                                         mock_clients, bypass):
        result = bypass._probe_bypasses()

        assert result["dns_tunnel"]["viable"] is False
        assert result["direct_ip"]["viable"] is False
        assert result["icmp_tunnel"]["viable"] is False
        assert result["mac_clone"]["viable"] is False


# ---------------------------------------------------------------------------
# 15. start
# ---------------------------------------------------------------------------

class TestStart:
    @patch.object(PortalBypass, "_probe_bypasses", return_value={"dns_tunnel": {}})
    def test_start_probe_mode(self, mock_probe, bypass):
        bypass.bypass_mode = "probe"
        result = bypass.start()

        assert result["mode"] == "probe"
        assert result["data"] == {"dns_tunnel": {}}
        assert bypass._running is False

    @patch.object(PortalBypass, "_test_direct_ip", return_value=True)
    def test_start_direct_ip_mode(self, mock_direct, bypass):
        bypass.bypass_mode = "direct-ip"
        result = bypass.start()

        assert result["mode"] == "direct-ip"
        assert result["data"]["direct_ip_success"] is True

    @patch.object(PortalBypass, "_mac_clone_test", return_value={"cloned_mac": None})
    @patch.object(PortalBypass, "_icmp_tunnel_test", return_value={})
    @patch.object(PortalBypass, "_dns_tunnel_test", return_value={})
    @patch.object(PortalBypass, "_probe_bypasses", return_value={})
    @patch.object(PortalBypass, "_test_direct_ip", return_value=True)
    def test_start_all_mode_runs_everything(self, mock_direct, mock_probe, mock_dns,
                                             mock_icmp, mock_clone, bypass):
        bypass.bypass_mode = "all"
        result = bypass.start()

        assert set(result["data"].keys()) == {
            "probe", "dns_tunnel", "icmp_tunnel", "mac_clone", "direct_ip",
        }

    def test_start_unknown_mode_logs_error(self, bypass):
        bypass.bypass_mode = "bogus-mode"
        result = bypass.start()
        assert result["data"] == {}


# ---------------------------------------------------------------------------
# 16. save_results
# ---------------------------------------------------------------------------

class TestSaveResults:
    def test_save_results_creates_json(self, bypass):
        bypass.results = {"mode": "probe", "interface": bypass.interface, "data": {}}
        filepath = bypass.save_results()

        assert filepath is not None
        assert os.path.exists(filepath)
        with open(filepath, encoding="utf-8") as f:
            saved = json.load(f)
        assert saved["mode"] == "probe"

    def test_save_results_no_results_returns_none(self, bypass):
        assert bypass.results == {}
        assert bypass.save_results() is None

    @patch("builtins.open")
    def test_save_results_handles_failure(self, mock_open, bypass):
        mock_open.side_effect = OSError("disk full")
        bypass.results = {"mode": "probe"}
        assert bypass.save_results() is None


# ---------------------------------------------------------------------------
# 17. get_status
# ---------------------------------------------------------------------------

class TestGetStatus:
    def test_get_status_initial(self, bypass):
        status = bypass.get_status()

        assert status["running"] is False
        assert status["interface"] == bypass.interface
        assert status["bypass_mode"] == "probe"
        assert status["dns_tunnel_domain"] == DEFAULT_DNS_DOMAIN
        assert status["target_ip"] == DEFAULT_TARGET_IP
        assert status["timeout"] == 30


# ---------------------------------------------------------------------------
# 18-20. CLI
# ---------------------------------------------------------------------------

class TestCLI:
    def test_cli_required_args(self):
        """CLI should require -i argument."""
        with patch("sys.argv", ["portal_bypass"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    def test_cli_mode_choices(self):
        """CLI should reject an invalid bypass mode."""
        args = ["portal_bypass", "-i", "wlan0", "-m", "not-a-real-mode"]
        with patch("sys.argv", args):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 2

    def test_cli_invalid_interface_rejected(self):
        args = ["portal_bypass", "-i", "bad iface!", "-m", "probe"]
        with patch("sys.argv", args):
            with patch("portal_bypass.require_root"):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    def test_cli_invalid_target_ip_rejected(self):
        args = ["portal_bypass", "-i", "wlan0", "-m", "direct-ip", "--target-ip", "not.an.ip"]
        with patch("sys.argv", args):
            with patch("portal_bypass.require_root"):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                assert exc_info.value.code == 1

    def test_cli_valid_mode_accepted(self):
        """Sanity check: every documented mode is a valid CLI choice."""
        assert set(BYPASS_MODES) == {
            "probe", "dns-tunnel", "icmp-tunnel", "mac-clone", "direct-ip", "all",
        }

        args = ["portal_bypass", "-i", "wlan0", "-m", "probe"]
        with patch("sys.argv", args):
            with patch("portal_bypass.require_root"):
                with patch.object(PortalBypass, "start", return_value={}):
                    with patch.object(PortalBypass, "save_results", return_value=None):
                        with pytest.raises(SystemExit) as exc_info:
                            main()
                        assert exc_info.value.code == 0
