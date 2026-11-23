"""Tests for deauth.py — DeauthAttacker (scapy mocked)."""

import sys
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Mock scapy before importing deauth
# ---------------------------------------------------------------------------
sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

from deauth import DeauthAttacker  # noqa: E402

# ---------------------------------------------------------------------------
# create_deauth_packet
# ---------------------------------------------------------------------------

class TestCreateDeauthPacket:
    """Tests for DeauthAttacker.create_deauth_packet."""

    def test_create_deauth_packet_returns_list(self):
        """Should return a list of two deauth packets (AP->client, client->AP)."""
        attacker = DeauthAttacker(
            interface="wlan0mon",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_client="11:22:33:44:55:66",
        )
        packets = attacker.create_deauth_packet()
        assert isinstance(packets, list)
        assert len(packets) == 2

    def test_create_deauth_packet_broadcast_default(self):
        """When no client is given, target_client defaults to broadcast."""
        attacker = DeauthAttacker(
            interface="wlan0mon",
            target_bssid="AA:BB:CC:DD:EE:FF",
        )
        assert attacker.target_client == "ff:ff:ff:ff:ff:ff"
        packets = attacker.create_deauth_packet()
        assert len(packets) == 2

    def test_create_deauth_packet_with_channel(self):
        """Channel setting should not affect packet creation."""
        attacker = DeauthAttacker(
            interface="wlan0mon",
            target_bssid="AA:BB:CC:DD:EE:FF",
            channel=6,
        )
        packets = attacker.create_deauth_packet()
        assert len(packets) == 2


# ---------------------------------------------------------------------------
# validate_mac integration
# ---------------------------------------------------------------------------

class TestValidateMacIntegration:
    """Test that DeauthAttacker uses the shared validate_mac correctly."""

    @patch("deauth.sendp")
    def test_send_deauth_rejects_invalid_bssid(self, mock_sendp):
        attacker = DeauthAttacker(
            interface="wlan0mon",
            target_bssid="INVALID",
        )
        result = attacker.send_deauth(count=1)
        assert result is False
        mock_sendp.assert_not_called()

    @patch("deauth.sendp")
    def test_send_deauth_rejects_invalid_client(self, mock_sendp):
        attacker = DeauthAttacker(
            interface="wlan0mon",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_client="NOT-VALID",
        )
        result = attacker.send_deauth(count=1)
        assert result is False
        mock_sendp.assert_not_called()

    @patch("deauth.sendp")
    def test_send_deauth_valid_macs(self, mock_sendp):
        """With valid MACs and mocked sendp, the attack should succeed."""
        attacker = DeauthAttacker(
            interface="wlan0mon",
            target_bssid="AA:BB:CC:DD:EE:FF",
            target_client="11:22:33:44:55:66",
        )
        result = attacker.send_deauth(count=2, delay=0)
        assert result is True
        assert attacker.packets_sent > 0
