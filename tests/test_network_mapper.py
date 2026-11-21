"""Tests for network_mapper.py — Network Discovery and Mapping."""

import json
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.l2", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

from network_mapper import NetworkMapper, DEFAULT_PORTS  # noqa: E402


@pytest.fixture
def mock_interface():
    return "eth0"


@pytest.fixture
def mapper(mock_interface):
    return NetworkMapper(interface=mock_interface)


class TestNetworkMapperInit:
    def test_default_init(self, mock_interface):
        m = NetworkMapper(interface=mock_interface)
        assert m.interface == mock_interface
        assert m.target_range == "192.168.1.0/24"
        assert m.port_scan is True
        assert m.common_ports == DEFAULT_PORTS
        assert m.timeout == 2.0
        assert m.output_file is None

    def test_custom_init(self, mock_interface):
        m = NetworkMapper(
            interface=mock_interface,
            target_range="10.0.0.0/24",
            port_scan=False,
            common_ports=[22, 80, 443],
            timeout=5.0,
            output_file="scan.json",
        )
        assert m.target_range == "10.0.0.0/24"
        assert m.port_scan is False
        assert m.common_ports == [22, 80, 443]
        assert m.timeout == 5.0
        assert m.output_file == "scan.json"


class TestDefaultPorts:
    def test_default_ports_not_empty(self):
        assert len(DEFAULT_PORTS) > 0

    def test_common_ports_included(self):
        assert 22 in DEFAULT_PORTS
        assert 80 in DEFAULT_PORTS
        assert 443 in DEFAULT_PORTS


class TestARPScan:
    @patch("network_mapper.srp")
    @patch("network_mapper.lookup_vendor", return_value="TestVendor")
    def test_arp_scan_returns_hosts(self, mock_vendor, mock_srp, mapper):
        mock_resp = MagicMock()
        mock_resp.hwsrc = "aa:bb:cc:dd:ee:ff"
        mock_resp.psrc = "192.168.1.10"
        mock_srp.return_value = ([(MagicMock(), mock_resp)], [])

        hosts = mapper.arp_scan()
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.1.10"
        assert hosts[0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert hosts[0]["vendor"] == "TestVendor"

    @patch("network_mapper.srp")
    def test_arp_scan_empty(self, mock_srp, mapper):
        mock_srp.return_value = ([], [])
        hosts = mapper.arp_scan()
        assert hosts == []

    @patch("network_mapper.srp", side_effect=Exception("Network error"))
    def test_arp_scan_error(self, mock_srp, mapper):
        hosts = mapper.arp_scan()
        assert hosts == []


class TestPortScan:
    @patch("socket.socket")
    def test_scan_port_open(self, mock_socket_cls, mapper):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH"
        mock_socket_cls.return_value = mock_sock

        result = mapper._scan_port("192.168.1.10", 22)
        assert result is not None
        assert result["port"] == 22
        assert result["state"] == "open"

    @patch("socket.socket")
    def test_scan_port_closed(self, mock_socket_cls, mapper):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1
        mock_socket_cls.return_value = mock_sock

        result = mapper._scan_port("192.168.1.10", 22)
        assert result is None

    @patch("socket.socket")
    def test_scan_port_timeout(self, mock_socket_cls, mapper):
        import socket
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = socket.timeout
        mock_socket_cls.return_value = mock_sock

        result = mapper._scan_port("192.168.1.10", 22)
        assert result is None

    @patch.object(NetworkMapper, "_scan_port")
    def test_port_scan_host(self, mock_scan, mock_interface):
        m = NetworkMapper(interface=mock_interface, common_ports=[22, 80, 443])
        mock_scan.side_effect = [
            {"port": 22, "state": "open", "banner": "SSH"},
            None,
            {"port": 443, "state": "open", "banner": ""},
        ]
        results = m.port_scan_host("192.168.1.10")
        assert len(results) == 2
        assert results[0]["port"] == 22
        assert results[1]["port"] == 443

    def test_port_scan_disabled(self, mock_interface):
        m = NetworkMapper(interface=mock_interface, port_scan=False)
        results = m.port_scan_host("192.168.1.10")
        assert results == []


class TestBannerGrab:
    def test_grab_banner_success(self, mapper):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9"
        result = mapper._grab_banner(mock_sock)
        assert "SSH" in result

    def test_grab_banner_timeout(self, mapper):
        import socket
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout
        result = mapper._grab_banner(mock_sock)
        assert result == ""


class TestScanNetwork:
    @patch.object(NetworkMapper, "arp_scan")
    @patch.object(NetworkMapper, "port_scan_host")
    def test_scan_network_full(self, mock_port_scan, mock_arp, mapper):
        mock_arp.return_value = [{"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Test"}]
        mock_port_scan.return_value = [{"port": 80, "state": "open", "banner": ""}]

        results = mapper.scan_network()
        assert results["host_count"] == 1
        assert len(results["hosts"]) == 1
        assert len(results["hosts"][0]["ports"]) == 1

    @patch.object(NetworkMapper, "arp_scan")
    def test_scan_network_no_port_scan(self, mock_arp, mock_interface):
        m = NetworkMapper(interface=mock_interface, port_scan=False)
        mock_arp.return_value = [{"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Test"}]

        results = m.scan_network()
        assert results["hosts"][0]["ports"] == []


class TestSaveResults:
    def test_save_json(self, mock_interface):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "scan.json")
            m = NetworkMapper(interface=mock_interface, output_file=filepath)
            results = {"hosts": [], "host_count": 0}
            m.save_results(results)
            assert os.path.exists(filepath)
            with open(filepath) as f:
                data = json.load(f)
            assert data["host_count"] == 0

    def test_save_csv(self, mock_interface):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "scan.csv")
            m = NetworkMapper(interface=mock_interface, output_file=filepath)
            results = {
                "hosts": [{"ip": "1.2.3.4", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Test", "ports": []}],
            }
            m.save_results(results)
            assert os.path.exists(filepath)

    def test_save_no_output(self, mapper):
        mapper.save_results({"hosts": []})


class TestPrintResults:
    def test_print_results_with_hosts(self, mapper, capsys):
        results = {
            "target_range": "192.168.1.0/24",
            "scan_time": 5.0,
            "hosts": [
                {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Router",
                 "ports": [{"port": 80, "state": "open", "banner": "nginx"}]},
            ],
        }
        mapper.print_results(results)
        output = capsys.readouterr().out
        assert "192.168.1.1" in output
        assert "80" in output

    def test_print_results_empty(self, mapper, capsys):
        mapper.print_results({"hosts": []})


class TestGetStats:
    def test_initial_stats(self, mapper):
        stats = mapper.get_stats()
        assert stats["hosts_found"] == 0
        assert stats["open_ports_found"] == 0
        assert stats["scan_time"] == 0.0


class TestStop:
    def test_stop_sets_event(self, mapper):
        mapper.stop()
        assert mapper._stop_event.is_set()
