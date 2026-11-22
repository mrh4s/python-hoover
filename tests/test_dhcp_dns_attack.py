"""Tests for dhcp_dns_attack.py -- DHCP/DNS Attack module."""

import json
import re
import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock scapy before importing the module under test.
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.l2", MagicMock())
sys.modules.setdefault("scapy.layers.inet", MagicMock())
sys.modules.setdefault("scapy.layers.dhcp", MagicMock())
sys.modules.setdefault("scapy.layers.dns", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())
sys.modules.setdefault("scapy.volatile", MagicMock())

from dhcp_dns_attack import (  # noqa: E402
    DHCPDNSAttack,
    ATTACK_MODES,
    DHCP_DISCOVER,
    DHCP_OFFER,
    DHCP_REQUEST,
    main,
)

from scapy.layers.l2 import Ether  # noqa: E402
from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.layers.dhcp import BOOTP, DHCP  # noqa: E402
from scapy.layers.dns import DNS  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def attack(mock_interface, tmp_path):
    return DHCPDNSAttack(
        interface=mock_interface,
        attack_mode="dhcp-starvation",
        output_dir=str(tmp_path / "captures"),
        timeout=5,
    )


def _make_dhcp_packet(msg_type_name, src_mac="aa:bb:cc:dd:ee:ff", xid=1234):
    """Build a mock packet carrying a DHCP layer with a message-type option."""
    pkt = MagicMock()
    pkt.haslayer = lambda cls: cls is DHCP

    dhcp_layer = MagicMock()
    dhcp_layer.options = [("message-type", _msg_type_value(msg_type_name)), "end"]

    ether_layer = MagicMock()
    ether_layer.src = src_mac
    ether_layer.dst = "ff:ff:ff:ff:ff:ff"

    bootp_layer = MagicMock()
    bootp_layer.xid = xid

    def getitem(cls):
        if cls is DHCP:
            return dhcp_layer
        if cls is Ether:
            return ether_layer
        if cls is BOOTP:
            return bootp_layer
        return MagicMock()

    pkt.__getitem__ = MagicMock(side_effect=getitem)
    return pkt


def _msg_type_value(name):
    return {
        "discover": DHCP_DISCOVER,
        "offer": DHCP_OFFER,
        "request": DHCP_REQUEST,
        "ack": 5,
    }[name]


def _make_dns_query_packet(qname="example.com.", qr=0, src_mac="aa:bb:cc:dd:ee:ff"):
    pkt = MagicMock()
    pkt.haslayer = lambda cls: cls is DNS

    dns_layer = MagicMock()
    dns_layer.qr = qr
    dns_layer.id = 42
    qd = MagicMock()
    qd.qname = qname.encode()
    dns_layer.qd = qd

    ether_layer = MagicMock()
    ether_layer.src = src_mac
    ether_layer.dst = "ff:ff:ff:ff:ff:ff"

    ip_layer = MagicMock()
    ip_layer.src = "192.168.1.50"
    ip_layer.dst = "192.168.1.1"

    udp_layer = MagicMock()
    udp_layer.sport = 55555

    def getitem(cls):
        if cls is DNS:
            return dns_layer
        if cls is Ether:
            return ether_layer
        if cls is IP:
            return ip_layer
        if cls is UDP:
            return udp_layer
        return MagicMock()

    pkt.__getitem__ = MagicMock(side_effect=getitem)
    return pkt


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

class TestInit:
    def test_default_init(self, mock_interface):
        a = DHCPDNSAttack(interface=mock_interface)
        assert a.interface == mock_interface
        assert a.attack_mode == "dhcp-starvation"
        assert a.timeout == 300
        assert a.output_dir == "captures"
        assert a.leases_requested == 0
        assert a.offers_received == 0
        assert a._running is False

    def test_custom_init(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(
            interface=mock_interface,
            attack_mode="dns-spoof",
            target_ip="10.0.0.5",
            spoof_domain="example.com",
            spoof_ip="10.0.0.9",
            rogue_gateway="10.0.0.1",
            rogue_dns="10.0.0.1",
            timeout=60,
            output_dir=str(tmp_path),
        )
        assert a.attack_mode == "dns-spoof"
        assert a.spoof_domain == "example.com"
        assert a.spoof_ip == "10.0.0.9"
        assert a.rogue_gateway == "10.0.0.1"
        assert a.rogue_dns == "10.0.0.1"
        assert a.timeout == 60

    def test_attack_modes_contains_expected(self):
        assert set(ATTACK_MODES) == {
            "dhcp-starvation", "dhcp-spoof", "dns-spoof", "all",
        }


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------

class TestPacketBuilders:
    def test_build_dhcp_discover_returns_layered_packet(self, attack):
        pkt = attack._build_dhcp_discover("02:11:22:33:44:55")
        # Scapy is mocked, so '/' composition returns MagicMock objects;
        # just verify no exception and a truthy object is returned.
        assert pkt is not None

    def test_build_dhcp_discover_calls_ether_with_mac(self, attack):
        mac = "02:11:22:33:44:55"
        with patch("dhcp_dns_attack.Ether") as mock_ether:
            attack._build_dhcp_discover(mac)
            _, kwargs = mock_ether.call_args
            assert kwargs["src"] == mac

    def test_build_dhcp_offer_uses_gateway_and_dns(self, attack):
        discover_pkt = _make_dhcp_packet("discover")
        with patch("dhcp_dns_attack.DHCP") as mock_dhcp:
            attack._build_dhcp_offer(discover_pkt, "10.0.0.1", "10.0.0.1")
            _, kwargs = mock_dhcp.call_args
            options = kwargs["options"]
            assert ("server_id", "10.0.0.1") in options
            assert ("name_server", "10.0.0.1") in options

    def test_build_dhcp_offer_handles_missing_layers_gracefully(self, attack):
        bad_pkt = MagicMock()
        bad_pkt.__getitem__ = MagicMock(side_effect=Exception("no layer"))
        # Should not raise even if Ether/BOOTP layers are unavailable.
        result = attack._build_dhcp_offer(bad_pkt, "10.0.0.1", "10.0.0.1")
        assert result is not None

    def test_build_dns_response_uses_spoof_ip(self, attack):
        query_pkt = _make_dns_query_packet(qname="evil.example.com.")
        with patch("dhcp_dns_attack.DNSRR") as mock_rr, \
                patch("dhcp_dns_attack.DNS") as mock_dns:
            attack._build_dns_response(query_pkt, "10.0.0.9")
            _, rr_kwargs = mock_rr.call_args
            assert rr_kwargs["rdata"] == "10.0.0.9"
            _, dns_kwargs = mock_dns.call_args
            assert dns_kwargs["qr"] == 1


# ---------------------------------------------------------------------------
# Random MAC generation
# ---------------------------------------------------------------------------

class TestRandomMac:
    def test_generate_random_mac_returns_string(self, attack):
        mac = attack._generate_random_mac()
        assert isinstance(mac, str)

    def test_generate_random_mac_uses_randmac(self, attack):
        with patch("dhcp_dns_attack.RandMAC") as mock_randmac:
            mock_randmac.return_value = "02:AA:BB:CC:DD:EE"
            mac = attack._generate_random_mac()
            mock_randmac.assert_called_once()
            assert mac == "02:AA:BB:CC:DD:EE"


# ---------------------------------------------------------------------------
# DHCP starvation
# ---------------------------------------------------------------------------

class TestDHCPStarvation:
    def test_starvation_sends_discovers_and_stops_on_timeout(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(
            interface=mock_interface,
            attack_mode="dhcp-starvation",
            timeout=1,
            output_dir=str(tmp_path),
        )
        with patch("dhcp_dns_attack.sendp") as mock_sendp, \
                patch.object(a, "_safe_sniff"):
            result = a._dhcp_starvation()

        assert mock_sendp.called
        assert result["attack_mode"] == "dhcp-starvation"
        assert result["leases_requested"] > 0
        assert result["unique_macs_used"] == result["leases_requested"]

    def test_starvation_stop_event_halts_sending(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(
            interface=mock_interface,
            attack_mode="dhcp-starvation",
            timeout=300,
            output_dir=str(tmp_path),
        )
        a._stop_event.set()
        with patch("dhcp_dns_attack.sendp") as mock_sendp, \
                patch.object(a, "_safe_sniff"):
            result = a._dhcp_starvation()
        mock_sendp.assert_not_called()
        assert result["leases_requested"] == 0

    def test_get_dhcp_message_type_discover(self, attack):
        pkt = _make_dhcp_packet("discover")
        assert attack._get_dhcp_message_type(pkt) == DHCP_DISCOVER

    def test_get_dhcp_message_type_handles_errors(self, attack):
        bad_pkt = MagicMock()
        bad_pkt.__getitem__ = MagicMock(side_effect=Exception("boom"))
        assert attack._get_dhcp_message_type(bad_pkt) is None


# ---------------------------------------------------------------------------
# DHCP spoof (rogue DHCP server)
# ---------------------------------------------------------------------------

class TestDHCPSpoof:
    def test_dhcp_spoof_responds_to_discover(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(
            interface=mock_interface,
            attack_mode="dhcp-spoof",
            rogue_gateway="10.0.0.1",
            rogue_dns="10.0.0.1",
            output_dir=str(tmp_path),
        )
        discover_pkt = _make_dhcp_packet("discover")

        def fake_sniff(filter_bpf, handler, timeout):
            handler(discover_pkt)

        with patch.object(a, "_safe_sniff", side_effect=fake_sniff), \
                patch("dhcp_dns_attack.sendp") as mock_sendp, \
                patch.object(a, "_build_dhcp_offer", return_value=MagicMock()):
            result = a._dhcp_spoof()

        assert mock_sendp.called
        assert result["offers_sent"] == 1
        assert result["rogue_gateway"] == "10.0.0.1"

    def test_dhcp_spoof_responds_to_request_with_ack(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(
            interface=mock_interface,
            attack_mode="dhcp-spoof",
            rogue_gateway="10.0.0.1",
            output_dir=str(tmp_path),
        )
        request_pkt = _make_dhcp_packet("request")

        def fake_sniff(filter_bpf, handler, timeout):
            handler(request_pkt)

        with patch.object(a, "_safe_sniff", side_effect=fake_sniff), \
                patch("dhcp_dns_attack.sendp") as mock_sendp, \
                patch.object(a, "_build_dhcp_offer", return_value=MagicMock()):
            result = a._dhcp_spoof()

        assert mock_sendp.called
        assert result["acks_sent"] == 1

    def test_dhcp_spoof_defaults_gateway_when_unset(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(interface=mock_interface, attack_mode="dhcp-spoof",
                           output_dir=str(tmp_path))
        with patch.object(a, "_safe_sniff"):
            result = a._dhcp_spoof()
        assert result["rogue_gateway"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# DNS spoof
# ---------------------------------------------------------------------------

class TestDNSSpoof:
    def test_dns_spoof_requires_domain_and_ip(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(interface=mock_interface, attack_mode="dns-spoof",
                           output_dir=str(tmp_path))
        result = a._dns_spoof()
        assert "error" in result

    def test_dns_spoof_matches_domain_and_sends_response(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(
            interface=mock_interface,
            attack_mode="dns-spoof",
            spoof_domain="example.com",
            spoof_ip="10.0.0.9",
            output_dir=str(tmp_path),
        )
        query_pkt = _make_dns_query_packet(qname="example.com.")

        def fake_sniff(filter_bpf, handler, timeout):
            handler(query_pkt)

        with patch.object(a, "_safe_sniff", side_effect=fake_sniff), \
                patch("dhcp_dns_attack.sendp") as mock_sendp, \
                patch.object(a, "_build_dns_response", return_value=MagicMock()):
            result = a._dns_spoof()

        assert mock_sendp.called
        assert result["dns_responses_sent"] == 1
        assert result["dns_queries_seen"] == 1

    def test_dns_spoof_ignores_non_matching_domain(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(
            interface=mock_interface,
            attack_mode="dns-spoof",
            spoof_domain="example.com",
            spoof_ip="10.0.0.9",
            output_dir=str(tmp_path),
        )
        query_pkt = _make_dns_query_packet(qname="other-site.com.")

        def fake_sniff(filter_bpf, handler, timeout):
            handler(query_pkt)

        with patch.object(a, "_safe_sniff", side_effect=fake_sniff), \
                patch("dhcp_dns_attack.sendp") as mock_sendp:
            result = a._dns_spoof()

        mock_sendp.assert_not_called()
        assert result["dns_responses_sent"] == 0
        assert result["dns_queries_seen"] == 1

    def test_dns_spoof_ignores_responses(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(
            interface=mock_interface,
            attack_mode="dns-spoof",
            spoof_domain="example.com",
            spoof_ip="10.0.0.9",
            output_dir=str(tmp_path),
        )
        response_pkt = _make_dns_query_packet(qname="example.com.", qr=1)

        def fake_sniff(filter_bpf, handler, timeout):
            handler(response_pkt)

        with patch.object(a, "_safe_sniff", side_effect=fake_sniff), \
                patch("dhcp_dns_attack.sendp") as mock_sendp:
            a._dns_spoof()

        mock_sendp.assert_not_called()


# ---------------------------------------------------------------------------
# start() / stop() / get_status() / save_results()
# ---------------------------------------------------------------------------

class TestStartStop:
    def test_start_invalid_interface(self, tmp_path):
        a = DHCPDNSAttack(interface="bad iface!", output_dir=str(tmp_path))
        result = a.start()
        assert "error" in result

    def test_start_invalid_mode(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(interface=mock_interface, attack_mode="bogus",
                           output_dir=str(tmp_path))
        result = a.start()
        assert "error" in result

    def test_start_dispatches_to_dhcp_starvation(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(interface=mock_interface, attack_mode="dhcp-starvation",
                           output_dir=str(tmp_path))
        with patch.object(a, "_dhcp_starvation", return_value={"ok": True}) as m, \
                patch.object(a, "save_results"):
            result = a.start()
        m.assert_called_once()
        assert result["dhcp_starvation"] == {"ok": True}
        assert a._running is False

    def test_start_dispatches_to_dhcp_spoof(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(interface=mock_interface, attack_mode="dhcp-spoof",
                           output_dir=str(tmp_path))
        with patch.object(a, "_dhcp_spoof", return_value={"ok": True}) as m, \
                patch.object(a, "save_results"):
            result = a.start()
        m.assert_called_once()
        assert result["dhcp_spoof"] == {"ok": True}

    def test_start_dispatches_to_dns_spoof(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(interface=mock_interface, attack_mode="dns-spoof",
                           output_dir=str(tmp_path))
        with patch.object(a, "_dns_spoof", return_value={"ok": True}) as m, \
                patch.object(a, "save_results"):
            result = a.start()
        m.assert_called_once()
        assert result["dns_spoof"] == {"ok": True}

    def test_start_all_runs_starvation_then_spoof(self, mock_interface, tmp_path):
        a = DHCPDNSAttack(interface=mock_interface, attack_mode="all",
                           output_dir=str(tmp_path))
        with patch.object(a, "_dhcp_starvation", return_value={"ok": 1}) as m1, \
                patch.object(a, "_dhcp_spoof", return_value={"ok": 2}) as m2, \
                patch.object(a, "save_results"):
            result = a.start()
        m1.assert_called_once()
        m2.assert_called_once()
        assert result["dhcp_starvation"] == {"ok": 1}
        assert result["dhcp_spoof"] == {"ok": 2}

    def test_stop_sets_stop_event_and_running_false(self, attack):
        attack._running = True
        attack.stop()
        assert attack._stop_event.is_set()
        assert attack._running is False


class TestGetStatus:
    def test_get_status_fields(self, attack):
        status = attack.get_status()
        assert status["interface"] == attack.interface
        assert status["attack_mode"] == "dhcp-starvation"
        assert "leases_requested" in status
        assert "offers_received" in status
        assert "dns_queries_seen" in status
        assert "events" in status
        assert isinstance(status["events"], list)

    def test_get_status_reflects_counters(self, attack):
        attack.leases_requested = 5
        attack.offers_received = 2
        status = attack.get_status()
        assert status["leases_requested"] == 5
        assert status["offers_received"] == 2


class TestSaveResults:
    def test_save_results_returns_none_when_no_data(self, attack):
        assert attack.save_results() is None

    def test_save_results_writes_json_file(self, attack):
        attack.leases_requested = 3
        attack.offers_received = 1
        path = attack.save_results()
        assert path is not None
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        assert data["leases_requested"] == 3
        assert data["offers_received"] == 1


# ---------------------------------------------------------------------------
# CLI parsing
# ---------------------------------------------------------------------------

class TestCLI:
    def test_cli_runs_starvation_mode(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            sys, "argv",
            ["dhcp_dns_attack.py", "-i", "wlan0", "-m", "dhcp-starvation",
             "-t", "1", "-o", str(tmp_path)],
        )
        with patch("dhcp_dns_attack.require_root"), \
                patch.object(DHCPDNSAttack, "start", return_value={"ok": True}) as mock_start:
            main()
        mock_start.assert_called_once()

    def test_cli_rejects_invalid_spoof_ip(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            sys, "argv",
            ["dhcp_dns_attack.py", "-i", "wlan0", "-m", "dns-spoof",
             "--spoof-domain", "example.com", "--spoof-ip", "not-an-ip",
             "-o", str(tmp_path)],
        )
        with patch("dhcp_dns_attack.require_root"):
            with pytest.raises(SystemExit):
                main()

    def test_cli_rejects_invalid_rogue_gateway(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            sys, "argv",
            ["dhcp_dns_attack.py", "-i", "wlan0", "-m", "dhcp-spoof",
             "--rogue-gateway", "999.999.999.999", "-o", str(tmp_path)],
        )
        with patch("dhcp_dns_attack.require_root"):
            with pytest.raises(SystemExit):
                main()

    def test_cli_rejects_invalid_mode(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            sys, "argv",
            ["dhcp_dns_attack.py", "-i", "wlan0", "-m", "not-a-real-mode",
             "-o", str(tmp_path)],
        )
        with pytest.raises(SystemExit):
            main()

    def test_cli_accepts_rogue_dns_and_gateway(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            sys, "argv",
            ["dhcp_dns_attack.py", "-i", "wlan0", "-m", "dhcp-spoof",
             "--rogue-gateway", "10.0.0.1", "--rogue-dns", "10.0.0.1",
             "-o", str(tmp_path)],
        )
        with patch("dhcp_dns_attack.require_root"), \
                patch.object(DHCPDNSAttack, "start", return_value={"ok": True}) as mock_start:
            main()
        mock_start.assert_called_once()
