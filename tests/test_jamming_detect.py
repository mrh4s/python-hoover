"""Tests for jamming_detect.py — RF jamming detection."""

import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

sys.modules.setdefault("scapy", MagicMock())
sys.modules.setdefault("scapy.layers", MagicMock())
sys.modules.setdefault("scapy.layers.dot11", MagicMock())
sys.modules.setdefault("scapy.sendrecv", MagicMock())

import jamming_detect  # noqa: E402
from jamming_detect import JammingDetector  # noqa: E402
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, RadioTap  # noqa: E402


@pytest.fixture
def det(mock_interface, tmp_path):
    return JammingDetector(mock_interface, channels=[6], output_dir=str(tmp_path))


def _pkt(layers, bssid="AA:BB:CC:DD:EE:FF", signal=None, noise=None):
    pkt = MagicMock()
    present = set(layers)
    pkt.haslayer = lambda cls: cls in present
    dot11 = MagicMock()
    dot11.addr2 = bssid
    dot11.addr3 = bssid
    rt = MagicMock()
    rt.dBm_AntSignal = signal
    rt.dBm_AntNoise = noise
    pkt.__getitem__ = lambda self, cls: rt if cls is RadioTap else dot11
    return pkt


def _beacon(bssid="AA:BB:CC:DD:EE:FF", signal=None, noise=None):
    layers = [Dot11, Dot11Beacon] + ([RadioTap] if signal is not None or noise is not None else [])
    return _pkt(layers, bssid, signal, noise)


def test_init_defaults(det):
    assert det.beacon_threshold == 0.5
    assert det.noise_threshold == -50
    assert det.deauth_threshold == 50
    assert det.scan_interval == 1.0
    assert det.timeout == 0
    assert det.alerts == []
    assert det.hopping is False


def test_init_default_channels(mock_interface):
    d = JammingDetector(mock_interface)
    assert d.channels == list(range(1, 14))
    assert d.hopping is True


def test_beacon_tracking(det):
    det.packet_handler(_beacon())
    det.packet_handler(_beacon())
    assert len(det._beacons["AA:BB:CC:DD:EE:FF"]) == 2
    assert det.get_status()["tracked_aps"] == 1


def test_signal_level_tracking(det):
    det.packet_handler(_beacon(signal=-55))
    assert det._signals["AA:BB:CC:DD:EE:FF"][0][1] == -55.0


def test_signal_missing_radiotap_field(det):
    det.packet_handler(_beacon(signal=None))
    assert not det._signals


def test_deauth_counting(det):
    det.packet_handler(_pkt([Dot11, Dot11Deauth]))
    det.packet_handler(_pkt([Dot11, Dot11Disas]))
    assert len(det._deauths) == 2


def test_packet_handler_ignores_non_dot11(det):
    det.packet_handler(_pkt([]))
    assert det.total_frames == 0


def test_beacon_loss_none_when_healthy(det):
    now = time.time()
    b = "AA:BB:CC:DD:EE:FF"
    det._beacon_first_seen[b] = now - 20
    det._beacon_channel[b] = 6
    det._beacons[b] = __import__("collections").deque(now - 20 + i * 0.1 for i in range(200))
    assert det._calculate_beacon_loss(b) == pytest.approx(0.0, abs=0.01)


def test_beacon_loss_high(det):
    from collections import deque
    now = time.time()
    b = "AA:BB:CC:DD:EE:FF"
    det._beacon_first_seen[b] = now - 20
    det._beacon_channel[b] = 6
    det._beacons[b] = deque(now - 20 + i for i in range(20))  # 1/sec vs 10/sec
    assert det._calculate_beacon_loss(b) == pytest.approx(0.9, abs=0.02)


def test_beacon_loss_unknown_bssid(det):
    assert det._calculate_beacon_loss("00:00:00:00:00:00") == 0.0


def test_beacon_loss_needs_observation_time(det):
    det.packet_handler(_beacon())
    assert det._calculate_beacon_loss("AA:BB:CC:DD:EE:FF") == 0.0


def test_noise_anomaly_detected(det):
    for _ in range(5):
        det.packet_handler(_beacon(noise=-40))
    assert det._detect_noise_anomaly() is True


def test_noise_normal(det):
    for _ in range(5):
        det.packet_handler(_beacon(noise=-95))
    assert det._detect_noise_anomaly() is False


def _seed_signals(det, bssid, old, new):
    from collections import deque
    now = time.time()
    dq = deque((now - 40 + i, old) for i in range(5))
    dq.extend((now - 5 + i * 0.5, new) for i in range(5))
    det._signals[bssid] = dq


def test_signal_anomaly_via_average_drop(det):
    _seed_signals(det, "AA:AA:AA:AA:AA:01", -40, -80)
    assert det._detect_noise_anomaly() is True


def test_deauth_storm_detection(det):
    det.deauth_threshold = 5
    for _ in range(4):
        det.packet_handler(_pkt([Dot11, Dot11Deauth]))
    assert det._detect_deauth_storm() is False
    det.packet_handler(_pkt([Dot11, Dot11Deauth]))
    assert det._detect_deauth_storm() is True


def test_signal_drop_multiple_aps(det):
    _seed_signals(det, "AA:AA:AA:AA:AA:01", -40, -80)
    _seed_signals(det, "AA:AA:AA:AA:AA:02", -45, -85)
    assert det._detect_signal_drop() is True


def test_signal_drop_single_ap_not_enough(det):
    _seed_signals(det, "AA:AA:AA:AA:AA:01", -40, -80)
    _seed_signals(det, "AA:AA:AA:AA:AA:02", -45, -46)
    assert det._detect_signal_drop() is False


def test_generate_alert_format_and_cooldown(det):
    det._generate_alert("deauth_storm", {"severity": "high", "channel": 6, "frames_per_min": 99})
    det._generate_alert("deauth_storm", {"severity": "high", "channel": 6})  # suppressed
    alerts = det.get_alerts()
    assert len(alerts) == 1
    a = alerts[0]
    assert a["type"] == "deauth_storm" and a["severity"] == "high" and a["channel"] == 6
    assert a["details"] == {"frames_per_min": 99}
    assert "T" in a["timestamp"]


def test_channel_hop(mock_interface, tmp_path):
    d = JammingDetector(mock_interface, channels=[1, 6, 11], scan_interval=0.01,
                        output_dir=str(tmp_path))
    calls = []
    d._set_channel = lambda ch: (calls.append(ch), len(calls) >= 4 and d.stop())
    d._channel_hop_thread()
    assert calls[:4] == [1, 6, 11, 1]
    assert d._dwell  # dwell time recorded


def test_channel_dead_alert(mock_interface, tmp_path):
    from collections import deque
    d = JammingDetector(mock_interface, channels=[1, 6], output_dir=str(tmp_path))
    now = time.time()
    d._channel_ever_active.add(6)
    d._dwell[6] = deque([(now - 30, now - 20), (now - 10, now - 5)])
    d._check_dead_channels()
    alerts = d.get_alerts()
    assert alerts and alerts[0]["type"] == "channel_dead" and alerts[0]["channel"] == 6


def test_save_results(det):
    det._generate_alert("noise_floor", {"severity": "high"})
    path = det.save_results()
    assert path and os.path.exists(path)
    data = json.load(open(path))
    assert data["alerts"][0]["type"] == "noise_floor"
    assert "status" in data


def test_save_results_failure(det):
    with patch("jamming_detect.os.makedirs", side_effect=OSError("nope")):
        assert det.save_results() is None


def test_get_status_and_stop(det):
    det.packet_handler(_beacon())
    s = det.get_status()
    assert s["total_frames"] == 1 and s["interface"] == det.interface
    det._running = True
    det.stop()
    assert det._stop_event.is_set() and det.get_status()["running"] is False


def test_cli_parsing():
    args = jamming_detect.build_parser().parse_args(
        ["-i", "wlan0mon", "-c", "1,6,11", "--beacon-threshold", "0.7",
         "--noise-threshold", "-60", "--deauth-threshold", "20",
         "--scan-interval", "2", "-t", "30", "-o", "out"])
    assert args.interface == "wlan0mon" and args.channels == "1,6,11"
    assert args.beacon_threshold == 0.7 and args.noise_threshold == -60
    assert args.deauth_threshold == 20 and args.scan_interval == 2.0
    assert args.timeout == 30 and args.output == "out"


def test_main_invokes_detector():
    with patch("jamming_detect.require_root"), \
         patch("jamming_detect.JammingDetector") as cls:
        jamming_detect.main(["-i", "wlan0mon", "-c", "1,6"])
        assert cls.call_args.kwargs["channels"] == [1, 6]
        cls.return_value.start.assert_called_once()


def test_main_rejects_bad_interface():
    with patch("jamming_detect.require_root"), pytest.raises(SystemExit):
        jamming_detect.main(["-i", "wlan0;rm"])
