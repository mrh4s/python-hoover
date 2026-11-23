"""Tests for mitm_attack.py -- MitM/ARP Spoofing Module."""

import json
import os
import sys
import tempfile
import time
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.l2", MagicMock())
sys.modules.setdefault("scapy.layers.inet", MagicMock())
sys.modules.setdefault("scapy.layers.dns", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.packet", MagicMock())

from mitm_attack import CREDENTIAL_FIELDS, DEFAULT_CAPTURE_PORTS, MitMAttack  # noqa: E402


@pytest.fixture
def mock_interface():
    return "eth0"


@pytest.fixture
def attack(mock_interface):
    return MitMAttack(
        interface=mock_interface,
        target_ip="192.168.1.100",
        gateway_ip="192.168.1.1",
    )


class TestMitMAttackInit:
    def test_default_init(self, mock_interface):
        m = MitMAttack(
            interface=mock_interface,
            target_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
        )
        assert m.interface == mock_interface
        assert m.target_ip == "192.168.1.100"
        assert m.gateway_ip == "192.168.1.1"
        assert m.output_dir == "captures"
        assert m.timeout == 300
        assert m.forward is True
        assert m.capture_ports == DEFAULT_CAPTURE_PORTS
        assert m._running is False
        assert m._start_time is None
        assert m._packets_captured == 0
        assert m._captured_credentials == []
        assert m._captured_dns == []

    def test_custom_init(self, mock_interface):
        m = MitMAttack(
            interface=mock_interface,
            target_ip="10.0.0.50",
            gateway_ip="10.0.0.1",
            output_dir="/tmp/test_output",
            timeout=600,
            forward=False,
            capture_ports=[80, 443],
        )
        assert m.target_ip == "10.0.0.50"
        assert m.gateway_ip == "10.0.0.1"
        assert m.output_dir == "/tmp/test_output"
        assert m.timeout == 600
        assert m.forward is False
        assert m.capture_ports == [80, 443]


class TestDefaultCapturePortsAndFields:
    def test_default_ports_not_empty(self):
        assert len(DEFAULT_CAPTURE_PORTS) > 0

    def test_common_ports_included(self):
        assert 80 in DEFAULT_CAPTURE_PORTS
        assert 443 in DEFAULT_CAPTURE_PORTS
        assert 8080 in DEFAULT_CAPTURE_PORTS

    def test_credential_fields_not_empty(self):
        assert len(CREDENTIAL_FIELDS) > 0

    def test_common_credential_fields(self):
        assert "username" in CREDENTIAL_FIELDS
        assert "password" in CREDENTIAL_FIELDS
        assert "email" in CREDENTIAL_FIELDS


class TestIPForwarding:
    @patch("builtins.open", mock_open(read_data="0"))
    def test_enable_ip_forwarding(self, attack):
        attack._enable_ip_forwarding()
        assert attack._original_forwarding == "0"
        # Verify write was called with "1"
        handle = open
        calls = handle.call_args_list
        # Second open call should be write mode
        assert any(c == call("/proc/sys/net/ipv4/ip_forward", "w") for c in calls)

    @patch("builtins.open", mock_open(read_data="1"))
    def test_enable_preserves_original(self, attack):
        attack._enable_ip_forwarding()
        assert attack._original_forwarding == "1"

    @patch("builtins.open", mock_open())
    def test_disable_ip_forwarding_restores_original(self, attack):
        attack._original_forwarding = "0"
        attack._disable_ip_forwarding()
        handle = open
        calls = handle.call_args_list
        assert any(c == call("/proc/sys/net/ipv4/ip_forward", "w") for c in calls)

    @patch("builtins.open", mock_open())
    def test_disable_ip_forwarding_defaults_to_zero(self, attack):
        attack._original_forwarding = None
        attack._disable_ip_forwarding()
        # Should write "0" when no original value is stored
        handle = open
        write_calls = handle().write.call_args_list
        assert any(c == call("0") for c in write_calls)

    @patch("builtins.open", side_effect=OSError("Permission denied"))
    def test_enable_ip_forwarding_error(self, mock_file, attack):
        with pytest.raises(OSError):
            attack._enable_ip_forwarding()


class TestMACResolution:
    @patch("mitm_attack.srp")
    def test_get_mac_success(self, mock_srp, attack):
        mock_resp = MagicMock()
        mock_resp.hwsrc = "aa:bb:cc:dd:ee:ff"
        mock_srp.return_value = ([(MagicMock(), mock_resp)], [])

        mac = attack._get_mac("192.168.1.100")
        assert mac == "aa:bb:cc:dd:ee:ff"

    @patch("mitm_attack.srp")
    def test_get_mac_no_response(self, mock_srp, attack):
        mock_srp.return_value = ([], [])
        mac = attack._get_mac("192.168.1.200")
        assert mac is None

    @patch("mitm_attack.srp", side_effect=Exception("Network error"))
    def test_get_mac_error(self, mock_srp, attack):
        mac = attack._get_mac("192.168.1.100")
        assert mac is None


class TestARPSpoof:
    @patch("mitm_attack.send")
    @patch("mitm_attack.ARP")
    def test_arp_spoof_sends_correct_packet(self, mock_arp_cls, mock_send, attack):
        mock_pkt = MagicMock()
        mock_arp_cls.return_value = mock_pkt

        attack._arp_spoof("192.168.1.100", "192.168.1.1", "aa:bb:cc:dd:ee:ff")

        mock_arp_cls.assert_called_once_with(
            op=2,
            pdst="192.168.1.100",
            hwdst="aa:bb:cc:dd:ee:ff",
            psrc="192.168.1.1",
        )
        mock_send.assert_called_once_with(mock_pkt, verbose=False)


class TestARPRestore:
    @patch("mitm_attack.send")
    @patch("mitm_attack.ARP")
    def test_restore_arp_sends_correct_packet(self, mock_arp_cls, mock_send, attack):
        mock_pkt = MagicMock()
        mock_arp_cls.return_value = mock_pkt

        attack._restore_arp(
            "192.168.1.100",
            "192.168.1.1",
            "aa:bb:cc:dd:ee:ff",
            "11:22:33:44:55:66",
        )

        mock_arp_cls.assert_called_once_with(
            op=2,
            pdst="192.168.1.100",
            hwdst="aa:bb:cc:dd:ee:ff",
            psrc="192.168.1.1",
            hwsrc="11:22:33:44:55:66",
        )
        mock_send.assert_called_once_with(mock_pkt, count=3, verbose=False)


class TestHTTPCredentialExtraction:
    def test_extract_http_credentials(self, attack):
        """Test extraction of credentials from a mock HTTP POST packet."""
        import mitm_attack as mod

        raw_layer = MagicMock()
        raw_layer.load = b"username=admin&password=test123"
        ip_mock = MagicMock()
        ip_mock.src = "192.168.1.100"
        ip_mock.dst = "10.0.0.1"
        tcp_mock = MagicMock()
        tcp_mock.dport = 80

        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True

        def getitem(key):
            if key is mod.Raw:
                return raw_layer
            if key is mod.IP:
                return ip_mock
            if key is mod.TCP:
                return tcp_mock
            return MagicMock()

        mock_packet.__getitem__ = MagicMock(side_effect=getitem)

        attack._extract_http_credentials(mock_packet)

        assert len(attack._captured_credentials) == 1
        creds = attack._captured_credentials[0]
        assert creds["fields"]["username"] == "admin"
        assert creds["fields"]["password"] == "test123"
        assert creds["src_ip"] == "192.168.1.100"
        assert creds["dst_ip"] == "10.0.0.1"
        assert creds["dst_port"] == 80

    def test_extract_http_no_credentials(self, attack):
        """Test that non-credential POST data produces no extraction."""
        import mitm_attack as mod

        raw_layer = MagicMock()
        raw_layer.load = b"action=search&query=hello"

        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True

        def getitem(key):
            if key is mod.Raw:
                return raw_layer
            return MagicMock()

        mock_packet.__getitem__ = MagicMock(side_effect=getitem)

        attack._extract_http_credentials(mock_packet)
        assert len(attack._captured_credentials) == 0

    def test_extract_http_credentials_url_encoded(self, attack):
        """Test extraction handles URL-encoded values."""
        import mitm_attack as mod

        raw_layer = MagicMock()
        raw_layer.load = b"email=user%40example.com&password=p%40ss"
        ip_mock = MagicMock()
        ip_mock.src = "192.168.1.100"
        ip_mock.dst = "10.0.0.1"
        tcp_mock = MagicMock()
        tcp_mock.dport = 80

        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True

        def getitem(key):
            if key is mod.Raw:
                return raw_layer
            if key is mod.IP:
                return ip_mock
            if key is mod.TCP:
                return tcp_mock
            return MagicMock()

        mock_packet.__getitem__ = MagicMock(side_effect=getitem)

        attack._extract_http_credentials(mock_packet)
        assert len(attack._captured_credentials) == 1
        creds = attack._captured_credentials[0]
        assert creds["fields"]["email"] == "user@example.com"
        assert creds["fields"]["password"] == "p@ss"


class TestDNSQueryExtraction:
    def test_extract_dns_query(self, attack):
        """Test DNS query extraction from a mock DNS packet."""
        import mitm_attack as mod

        dnsqr_mock = MagicMock()
        dnsqr_mock.qname = b"example.com."
        ip_mock = MagicMock()
        ip_mock.src = "192.168.1.100"

        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True

        def getitem(key):
            if key is mod.DNSQR:
                return dnsqr_mock
            if key is mod.IP:
                return ip_mock
            return MagicMock()

        mock_packet.__getitem__ = MagicMock(side_effect=getitem)

        attack._extract_dns_query(mock_packet)
        assert len(attack._captured_dns) == 1
        assert attack._captured_dns[0]["query"] == "example.com"
        assert attack._captured_dns[0]["src_ip"] == "192.168.1.100"

    def test_extract_dns_query_string(self, attack):
        """Test DNS query extraction when qname is already a string."""
        import mitm_attack as mod

        dnsqr_mock = MagicMock()
        dnsqr_mock.qname = "google.com."
        ip_mock = MagicMock()
        ip_mock.src = "192.168.1.100"

        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = True

        def getitem(key):
            if key is mod.DNSQR:
                return dnsqr_mock
            if key is mod.IP:
                return ip_mock
            return MagicMock()

        mock_packet.__getitem__ = MagicMock(side_effect=getitem)

        attack._extract_dns_query(mock_packet)
        assert len(attack._captured_dns) == 1
        assert attack._captured_dns[0]["query"] == "google.com"


class TestPacketHandler:
    def test_packet_handler_increments_count(self, attack):
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False

        attack.packet_handler(mock_packet)
        assert attack._packets_captured == 1

    def test_packet_handler_multiple_packets(self, attack):
        mock_packet = MagicMock()
        mock_packet.haslayer.return_value = False

        for _ in range(5):
            attack.packet_handler(mock_packet)
        assert attack._packets_captured == 5

    @patch.object(MitMAttack, "_extract_http_credentials")
    @patch.object(MitMAttack, "_extract_dns_query")
    def test_packet_handler_calls_extractors(self, mock_dns, mock_http, attack):

        mock_packet = MagicMock()

        def haslayer(layer):
            return True

        mock_packet.haslayer = haslayer

        attack.packet_handler(mock_packet)
        mock_http.assert_called_once_with(mock_packet)
        mock_dns.assert_called_once_with(mock_packet)


class TestStartStop:
    @patch.object(MitMAttack, "_sniff_traffic")
    @patch.object(MitMAttack, "_spoof_loop")
    @patch.object(MitMAttack, "_get_mac")
    @patch.object(MitMAttack, "_enable_ip_forwarding")
    def test_start_success(self, mock_fwd, mock_mac, mock_spoof, mock_sniff, attack):
        mock_mac.side_effect = ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]

        attack.start()

        mock_fwd.assert_called_once()
        assert mock_mac.call_count == 2
        assert attack._running is True
        assert attack._target_mac == "aa:bb:cc:dd:ee:ff"
        assert attack._gateway_mac == "11:22:33:44:55:66"
        assert attack._start_time is not None

        # Clean up
        attack._stop_event.set()

    @patch.object(MitMAttack, "_get_mac")
    @patch.object(MitMAttack, "_enable_ip_forwarding")
    @patch.object(MitMAttack, "_disable_ip_forwarding")
    def test_start_target_mac_fail(self, mock_disable, mock_enable, mock_mac, attack):
        mock_mac.return_value = None

        attack.start()

        assert attack._running is False
        mock_disable.assert_called_once()

    @patch.object(MitMAttack, "_get_mac")
    @patch.object(MitMAttack, "_enable_ip_forwarding")
    @patch.object(MitMAttack, "_disable_ip_forwarding")
    def test_start_gateway_mac_fail(self, mock_disable, mock_enable, mock_mac, attack):
        mock_mac.side_effect = ["aa:bb:cc:dd:ee:ff", None]

        attack.start()

        assert attack._running is False
        mock_disable.assert_called_once()

    @patch.object(MitMAttack, "_get_mac")
    def test_start_no_forward(self, mock_mac, mock_interface):
        m = MitMAttack(
            interface=mock_interface,
            target_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            forward=False,
        )
        mock_mac.side_effect = ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]

        with patch.object(m, "_enable_ip_forwarding") as mock_enable:
            m.start()
            mock_enable.assert_not_called()

        m._stop_event.set()

    @patch.object(MitMAttack, "_save_captured_data")
    @patch.object(MitMAttack, "_restore_arp")
    @patch.object(MitMAttack, "_disable_ip_forwarding")
    def test_stop_restores_arp(self, mock_disable, mock_restore, mock_save, attack):
        attack._target_mac = "aa:bb:cc:dd:ee:ff"
        attack._gateway_mac = "11:22:33:44:55:66"
        attack._running = True

        attack.stop()

        assert attack._running is False
        assert mock_restore.call_count == 2
        mock_disable.assert_called_once()
        mock_save.assert_called_once()

    @patch.object(MitMAttack, "_save_captured_data")
    @patch.object(MitMAttack, "_restore_arp", side_effect=Exception("Network error"))
    @patch.object(MitMAttack, "_disable_ip_forwarding")
    def test_stop_disables_forwarding_on_restore_error(
        self, mock_disable, mock_restore, mock_save, attack
    ):
        """IP forwarding must be disabled even if ARP restore fails."""
        attack._target_mac = "aa:bb:cc:dd:ee:ff"
        attack._gateway_mac = "11:22:33:44:55:66"
        attack._running = True

        attack.stop()

        mock_disable.assert_called_once()

    @patch.object(MitMAttack, "_save_captured_data")
    @patch.object(MitMAttack, "_disable_ip_forwarding")
    def test_stop_no_forward(self, mock_disable, mock_save, mock_interface):
        m = MitMAttack(
            interface=mock_interface,
            target_ip="192.168.1.100",
            gateway_ip="192.168.1.1",
            forward=False,
        )
        m._running = True
        m.stop()
        mock_disable.assert_not_called()


class TestGetCapturedData:
    def test_empty_captured_data(self, attack):
        data = attack.get_captured_data()
        assert data["credentials"] == []
        assert data["dns_queries"] == []
        assert data["target_ip"] == "192.168.1.100"
        assert data["gateway_ip"] == "192.168.1.1"
        assert data["interface"] == "eth0"
        assert "timestamp" in data

    def test_captured_data_with_entries(self, attack):
        attack._captured_credentials.append(
            {
                "timestamp": "2024-01-01 12:00:00",
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "dst_port": 80,
                "fields": {"username": "admin", "password": "secret"},
            }
        )
        attack._captured_dns.append(
            {
                "timestamp": "2024-01-01 12:00:01",
                "src_ip": "192.168.1.100",
                "query": "example.com",
            }
        )

        data = attack.get_captured_data()
        assert len(data["credentials"]) == 1
        assert len(data["dns_queries"]) == 1
        assert data["credentials"][0]["fields"]["username"] == "admin"
        assert data["dns_queries"][0]["query"] == "example.com"


class TestGetStatus:
    def test_initial_status(self, attack):
        status = attack.get_status()
        assert status["running"] is False
        assert status["target_ip"] == "192.168.1.100"
        assert status["gateway_ip"] == "192.168.1.1"
        assert status["target_mac"] is None
        assert status["gateway_mac"] is None
        assert status["packets_captured"] == 0
        assert status["credentials_found"] == 0
        assert status["dns_queries_captured"] == 0
        assert status["elapsed_time"] == 0.0
        assert status["forward"] is True

    def test_status_while_running(self, attack):
        attack._running = True
        attack._start_time = time.time() - 10
        attack._packets_captured = 42
        attack._captured_credentials.append({"fields": {}})
        attack._captured_dns.append({"query": "test"})

        status = attack.get_status()
        assert status["running"] is True
        assert status["packets_captured"] == 42
        assert status["credentials_found"] == 1
        assert status["dns_queries_captured"] == 1
        assert status["elapsed_time"] >= 9.0


class TestSaveCapturedData:
    def test_save_data_to_json(self, attack):
        with tempfile.TemporaryDirectory() as tmpdir:
            attack.output_dir = tmpdir
            attack._captured_credentials.append(
                {
                    "timestamp": "2024-01-01 12:00:00",
                    "src_ip": "192.168.1.100",
                    "dst_ip": "10.0.0.1",
                    "dst_port": 80,
                    "fields": {"username": "admin"},
                }
            )
            attack._save_captured_data()

            files = os.listdir(tmpdir)
            assert len(files) == 1
            assert files[0].startswith("mitm_capture_")
            assert files[0].endswith(".json")

            with open(os.path.join(tmpdir, files[0])) as f:
                data = json.load(f)
            assert len(data["credentials"]) == 1
            assert data["target_ip"] == "192.168.1.100"

    def test_save_no_data(self, attack):
        with tempfile.TemporaryDirectory() as tmpdir:
            attack.output_dir = tmpdir
            attack._save_captured_data()
            # No file should be created when there's no data
            assert len(os.listdir(tmpdir)) == 0


class TestCLIArguments:
    def test_cli_basic_args(self):
        """Test that CLI parses required arguments."""
        with patch(
            "sys.argv",
            [
                "mitm_attack.py",
                "-i",
                "eth0",
                "--target",
                "192.168.1.100",
                "--gateway",
                "192.168.1.1",
            ],
        ):
            parser = _build_parser()
            args = parser.parse_args()
            assert args.interface == "eth0"
            assert args.target == "192.168.1.100"
            assert args.gateway == "192.168.1.1"
            assert args.output_dir == "captures"
            assert args.timeout == 300
            assert args.no_forward is False
            assert args.ports is None
            assert args.verbose is False

    def test_cli_custom_args(self):
        """Test CLI with custom arguments."""
        with patch(
            "sys.argv",
            [
                "mitm_attack.py",
                "-i",
                "wlan0",
                "--target",
                "10.0.0.50",
                "--gateway",
                "10.0.0.1",
                "-o",
                "/tmp/output",
                "-t",
                "600",
                "--no-forward",
                "-p",
                "80,443,8080",
                "-v",
            ],
        ):
            parser = _build_parser()
            args = parser.parse_args()
            assert args.interface == "wlan0"
            assert args.target == "10.0.0.50"
            assert args.gateway == "10.0.0.1"
            assert args.output_dir == "/tmp/output"
            assert args.timeout == 600
            assert args.no_forward is True
            assert args.ports == "80,443,8080"
            assert args.verbose is True


class TestPortListParsing:
    def test_parse_valid_port_list(self):
        """Test parsing a comma-separated port list."""
        ports_str = "80,443,8080"
        ports = [int(p.strip()) for p in ports_str.split(",")]
        assert ports == [80, 443, 8080]

    def test_parse_port_list_with_spaces(self):
        """Test parsing port list with spaces."""
        ports_str = "80, 443, 8080"
        ports = [int(p.strip()) for p in ports_str.split(",")]
        assert ports == [80, 443, 8080]

    def test_parse_single_port(self):
        """Test parsing a single port."""
        ports_str = "80"
        ports = [int(p.strip()) for p in ports_str.split(",")]
        assert ports == [80]

    def test_parse_invalid_port_list(self):
        """Test that invalid port list raises ValueError."""
        ports_str = "80,abc,443"
        with pytest.raises(ValueError):
            [int(p.strip()) for p in ports_str.split(",")]


class TestFullLifecycle:
    @patch.object(MitMAttack, "_save_captured_data")
    @patch.object(MitMAttack, "_restore_arp")
    @patch.object(MitMAttack, "_disable_ip_forwarding")
    @patch.object(MitMAttack, "_sniff_traffic")
    @patch.object(MitMAttack, "_spoof_loop")
    @patch.object(MitMAttack, "_get_mac")
    @patch.object(MitMAttack, "_enable_ip_forwarding")
    def test_start_and_stop(
        self,
        mock_enable,
        mock_mac,
        mock_spoof,
        mock_sniff,
        mock_disable,
        mock_restore,
        mock_save,
        attack,
    ):
        """Test full start-stop lifecycle."""
        mock_mac.side_effect = ["aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"]

        attack.start()
        assert attack._running is True

        attack.stop()
        assert attack._running is False
        mock_restore.assert_called()
        mock_disable.assert_called_once()
        mock_save.assert_called_once()


def _build_parser():
    """Build the CLI argument parser (duplicated from main for testing)."""
    import argparse

    parser = argparse.ArgumentParser(description="MitM Attack")
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--gateway", required=True)
    parser.add_argument("-o", "--output-dir", default="captures")
    parser.add_argument("-t", "--timeout", type=int, default=300)
    parser.add_argument("--no-forward", action="store_true")
    parser.add_argument("-p", "--ports")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser
