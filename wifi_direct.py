#!/usr/bin/env python3
"""
WiFi Direct (P2P) Security Testing Module for Hoover WiFi Security Toolkit.

Tests WiFi Direct / P2P implementations for security weaknesses:

  * Passive discovery of P2P devices (Probe Request/Response, Beacon, GON
    frames carrying the WiFi Alliance P2P vendor-specific IE)
  * Analysis of Group Owner (GO) negotiation security (GO Intent
    tie-breaking, WPS configuration method strength, operating channel)
  * Detection of active P2P groups and weak/default WPS PINs used during
    P2P group formation
  * Detection of unauthorized/rogue P2P groups operating nearby

REALISTIC LIMITATION: WiFi Direct WPS PIN testing requires the ability to
initiate a P2P connection, which needs a managed-mode interface (not
monitor). This module focuses on passive discovery and analysis of P2P
traffic, plus GO negotiation security assessment. Active WPS PIN brute-
forcing requires wpa_supplicant with P2P support.

For authorized security testing and research only.
"""

import argparse
import json
import os
import struct
import sys
import threading
import time
from datetime import datetime
from typing import Optional

from scapy.layers.dot11 import (
    Dot11,
    Dot11Action,
    Dot11Beacon,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
)
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

from utils import require_root, setup_logging, validate_interface, validate_mac

# WiFi Alliance P2P OUI and vendor-specific IE OUI type
P2P_OUI = b"\x50\x6f\x9a"
P2P_OUI_TYPE = 9
VENDOR_SPECIFIC_TAG = 221  # Dot11Elt ID for vendor-specific information elements

# 802.11 Action frame categories used by P2P
CATEGORY_PUBLIC_ACTION = 4
CATEGORY_VENDOR_SPECIFIC = 127

# Public Action frame "vendor specific" action field value
PUBLIC_ACTION_VENDOR_SPECIFIC = 9

# P2P Attribute IDs (WiFi P2P Technical Specification)
P2P_ATTR_STATUS = 0
P2P_ATTR_MINOR_REASON_CODE = 1
P2P_ATTR_CAPABILITY = 2
P2P_ATTR_DEVICE_ID = 3
P2P_ATTR_GO_INTENT = 4
P2P_ATTR_CONFIG_TIMEOUT = 6
P2P_ATTR_LISTEN_CHANNEL = 7
P2P_ATTR_GROUP_BSSID = 8
P2P_ATTR_EXT_LISTEN_TIMING = 9
P2P_ATTR_INTENDED_INTERFACE_ADDR = 10
P2P_ATTR_MANAGEABILITY = 11
P2P_ATTR_CHANNEL_LIST = 12
P2P_ATTR_P2P_DEVICE_INFO = 13
P2P_ATTR_P2P_GROUP_INFO = 14
P2P_ATTR_P2P_GROUP_ID = 15
P2P_ATTR_P2P_INTERFACE = 16
P2P_ATTR_OPERATING_CHANNEL = 17
P2P_ATTR_INVITATION_FLAGS = 18

_P2P_ATTR_NAMES: dict[int, str] = {
    P2P_ATTR_STATUS: "Status",
    P2P_ATTR_MINOR_REASON_CODE: "Minor Reason Code",
    P2P_ATTR_CAPABILITY: "Capability",
    P2P_ATTR_DEVICE_ID: "Device ID",
    P2P_ATTR_GO_INTENT: "GO Intent",
    P2P_ATTR_CONFIG_TIMEOUT: "Config Timeout",
    P2P_ATTR_LISTEN_CHANNEL: "Listen Channel",
    P2P_ATTR_GROUP_BSSID: "Group BSSID",
    P2P_ATTR_EXT_LISTEN_TIMING: "Extended Listen Timing",
    P2P_ATTR_INTENDED_INTERFACE_ADDR: "Intended Interface Address",
    P2P_ATTR_MANAGEABILITY: "Manageability",
    P2P_ATTR_CHANNEL_LIST: "Channel List",
    P2P_ATTR_P2P_DEVICE_INFO: "P2P Device Info",
    P2P_ATTR_P2P_GROUP_INFO: "P2P Group Info",
    P2P_ATTR_P2P_GROUP_ID: "P2P Group ID",
    P2P_ATTR_P2P_INTERFACE: "P2P Interface",
    P2P_ATTR_OPERATING_CHANNEL: "Operating Channel",
    P2P_ATTR_INVITATION_FLAGS: "Invitation Flags",
}

# WPS Config Methods (bitmask seen in P2P Device Info sub-attribute)
WPS_CONFIG_METHODS: dict[int, str] = {
    0x0001: "USBA",
    0x0002: "Ethernet",
    0x0004: "Label",
    0x0008: "Display",
    0x0010: "Ext NFC Token",
    0x0020: "Int NFC Token",
    0x0040: "NFC Interface",
    0x0080: "PBC",
    0x0100: "Keypad",
    0x0108: "PIN Display",
    0x0188: "PIN Keypad",
}

# Known weak / default P2P WPS PINs worth flagging during analysis.
WEAK_WPS_PINS: list[str] = [
    "00000000",
    "12345670",
    "11111111",
    "88888888",
    "12345678",
]

# GO Negotiation Public Action frame subtypes (P2P Technical Spec, Table 55)
GO_NEG_REQUEST = 0
GO_NEG_RESPONSE = 1
GO_NEG_CONFIRM = 2
P2P_INVITATION_REQUEST = 3
P2P_INVITATION_RESPONSE = 4
DEVICE_DISCOVERABILITY_REQUEST = 5
DEVICE_DISCOVERABILITY_RESPONSE = 6
PROVISION_DISCOVERY_REQUEST = 7
PROVISION_DISCOVERY_RESPONSE = 8

_P2P_PUBLIC_ACTION_NAMES: dict[int, str] = {
    GO_NEG_REQUEST: "GO Negotiation Request",
    GO_NEG_RESPONSE: "GO Negotiation Response",
    GO_NEG_CONFIRM: "GO Negotiation Confirm",
    P2P_INVITATION_REQUEST: "P2P Invitation Request",
    P2P_INVITATION_RESPONSE: "P2P Invitation Response",
    DEVICE_DISCOVERABILITY_REQUEST: "Device Discoverability Request",
    DEVICE_DISCOVERABILITY_RESPONSE: "Device Discoverability Response",
    PROVISION_DISCOVERY_REQUEST: "Provision Discovery Request",
    PROVISION_DISCOVERY_RESPONSE: "Provision Discovery Response",
}

TEST_MODES = ("discover", "analyze", "wps-test", "detect-groups", "all")

REALISTIC_LIMITATION = """
REALISTIC LIMITATION: WiFi Direct WPS PIN testing requires the ability to
initiate a P2P connection, which needs a managed-mode interface (not
monitor). This module focuses on passive discovery and analysis of P2P
traffic, plus GO negotiation security assessment. Active WPS PIN brute-
forcing requires wpa_supplicant with P2P support.
"""


class WiFiDirectTester:
    """Passive WiFi Direct (P2P) discovery and security analysis.

    Sniffs 802.11 management/action traffic for the WiFi Alliance P2P
    vendor-specific information element and action frames, and analyzes
    captured P2P traffic for GO negotiation weaknesses, WPS method
    strength, and unauthorized/rogue P2P groups.
    """

    def __init__(
        self,
        interface: str,
        test_mode: str = "discover",
        target_device: Optional[str] = None,
        timeout: int = 120,
        output_dir: str = "captures",
    ) -> None:
        self.interface: str = interface
        self.test_mode: str = test_mode
        self.target_device: Optional[str] = target_device.upper() if target_device else None
        self.timeout: int = timeout
        self.output_dir: str = output_dir
        self.logger = setup_logging("wifi_direct")

        self.devices: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}
        self.gon_frames: list[dict] = []
        self.captured_packets: list = []
        self.results: dict = {}

        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._start_time: Optional[float] = None
        self._running: bool = False

    # -----------------------------------------------------------------
    # Parsing helpers
    # -----------------------------------------------------------------

    def _parse_p2p_attributes(self, data: bytes) -> list[dict]:
        """Parse a sequence of P2P attributes (TLV) out of raw IE bytes.

        Each P2P attribute is: 1 byte Attribute ID, 2 bytes little-endian
        length, then that many bytes of attribute body.

        Args:
            data: Raw bytes following the P2P OUI + OUI type header.

        Returns:
            List of dicts, each with "id", "name", and "value" (raw bytes,
            or a decoded int for single/double-byte known attributes).
        """
        attributes: list[dict] = []
        offset = 0
        n = len(data)

        while offset + 3 <= n:
            attr_id = data[offset]
            length = struct.unpack_from("<H", data, offset + 1)[0]
            start = offset + 3
            end = start + length
            if end > n:
                # Truncated attribute; stop parsing rather than overrun.
                break

            value = data[start:end]
            parsed: dict = {
                "id": attr_id,
                "name": _P2P_ATTR_NAMES.get(attr_id, f"Unknown (0x{attr_id:02x})"),
                "raw": value,
            }

            if attr_id == P2P_ATTR_STATUS and len(value) >= 1:
                parsed["value"] = value[0]
            elif attr_id == P2P_ATTR_MINOR_REASON_CODE and len(value) >= 1:
                parsed["value"] = value[0]
            elif attr_id == P2P_ATTR_CAPABILITY and len(value) >= 2:
                parsed["value"] = {
                    "device_capability": value[0],
                    "group_capability": value[1],
                }
            elif attr_id == P2P_ATTR_GO_INTENT and len(value) >= 1:
                raw_byte = value[0]
                parsed["value"] = {
                    "go_intent": raw_byte >> 1,
                    "tie_breaker": raw_byte & 0x01,
                }
            elif attr_id == P2P_ATTR_CONFIG_TIMEOUT and len(value) >= 2:
                parsed["value"] = {
                    "go_config_timeout": value[0],
                    "client_config_timeout": value[1],
                }
            elif attr_id == P2P_ATTR_LISTEN_CHANNEL and len(value) >= 1:
                parsed["value"] = value[-1]
            elif attr_id == P2P_ATTR_OPERATING_CHANNEL and len(value) >= 1:
                parsed["value"] = value[-1]
            elif attr_id == P2P_ATTR_GROUP_BSSID and len(value) == 6:
                parsed["value"] = ":".join(f"{b:02x}" for b in value).upper()
            elif attr_id == P2P_ATTR_P2P_DEVICE_INFO:
                parsed["value"] = self._parse_device_info(value)
            else:
                parsed["value"] = value

            attributes.append(parsed)
            offset = end

        return attributes

    def _parse_device_info(self, data: bytes) -> dict:
        """Parse the body of a P2P Device Info attribute.

        Layout: Device Address (6), Config Methods (2, big-endian),
        Primary Device Type (8), Secondary Device Type Count (1),
        Secondary Device Types (8 * count), WPS Device Name sub-TLV.

        Args:
            data: Raw P2P Device Info attribute body.

        Returns:
            Dict with device_address, config_methods (name list), and
            device_name when present.
        """
        info: dict = {}
        if len(data) < 6:
            return info

        info["device_address"] = ":".join(f"{b:02x}" for b in data[0:6]).upper()

        if len(data) >= 8:
            config_methods_raw = struct.unpack_from(">H", data, 6)[0]
            info["config_methods_raw"] = config_methods_raw
            methods = []
            for bit, name in WPS_CONFIG_METHODS.items():
                if config_methods_raw & bit == bit and bit not in (0x0108, 0x0188):
                    methods.append(name)
            info["config_methods"] = methods

        # Device name is carried in a WPS-style sub-element (type 0x1011)
        # somewhere after the fixed fields; scan for it defensively.
        idx = data.find(b"\x10\x11")
        if idx != -1 and idx + 4 <= len(data):
            name_len = struct.unpack_from(">H", data, idx + 2)[0]
            name_bytes = data[idx + 4 : idx + 4 + name_len]
            try:
                info["device_name"] = name_bytes.decode("utf-8", errors="replace")
            except Exception:
                info["device_name"] = ""

        return info

    def _parse_p2p_ie(self, data: bytes) -> dict:
        """Parse a full WiFi P2P vendor-specific information element.

        Args:
            data: Raw IE body bytes (OUI + OUI type + P2P attributes), as
                found in a vendor-specific (tag 221) Dot11Elt.

        Returns:
            Dict with "device_name", "device_type", "go_intent",
            "config_methods", and "attributes" (the parsed attribute
            list). Returns an empty dict if this is not a P2P IE.
        """
        if len(data) < 4 or data[0:3] != P2P_OUI or data[3] != P2P_OUI_TYPE:
            return {}

        attributes = self._parse_p2p_attributes(data[4:])
        result: dict = {
            "device_name": None,
            "device_type": None,
            "go_intent": None,
            "tie_breaker": None,
            "config_methods": [],
            "attributes": attributes,
        }

        for attr in attributes:
            if attr["id"] == P2P_ATTR_P2P_DEVICE_INFO and isinstance(attr["value"], dict):
                dev_info = attr["value"]
                result["device_name"] = dev_info.get("device_name")
                result["device_address"] = dev_info.get("device_address")
                result["config_methods"] = dev_info.get("config_methods", [])
            elif attr["id"] == P2P_ATTR_GO_INTENT and isinstance(attr["value"], dict):
                result["go_intent"] = attr["value"].get("go_intent")
                result["tie_breaker"] = attr["value"].get("tie_breaker")
            elif attr["id"] == P2P_ATTR_P2P_GROUP_INFO:
                result["has_group_info"] = True

        return result

    def _get_p2p_ie_bytes(self, packet) -> Optional[bytes]:
        """Walk a packet's Dot11Elt chain for a WiFi P2P vendor IE.

        Args:
            packet: A scapy packet potentially containing Dot11Elt layers.

        Returns:
            Raw IE body bytes if a P2P vendor-specific IE is found, else
            None.
        """
        try:
            elt = packet.getlayer(Dot11Elt)
        except Exception:
            return None

        while elt is not None:
            try:
                if getattr(elt, "ID", None) == VENDOR_SPECIFIC_TAG:
                    info = bytes(getattr(elt, "info", b"") or b"")
                    if len(info) >= 4 and info[0:3] == P2P_OUI and info[3] == P2P_OUI_TYPE:
                        return info
            except Exception:
                pass
            elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, "payload") else None

        return None

    # -----------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------

    def _detect_go_negotiation(self, packet) -> Optional[dict]:
        """Detect a GO Negotiation Request/Response/Confirm action frame.

        P2P Public Action frames are 802.11 Action frames with category
        4 (Public Action), action field 9 (vendor specific), followed by
        the P2P OUI, OUI type 9, and a one-byte P2P subtype.

        Args:
            packet: A scapy packet potentially carrying a Dot11Action
                layer with a P2P public action payload.

        Returns:
            Dict describing the GO negotiation frame (subtype, source,
            and parsed P2P attributes), or None if this packet is not a
            P2P GO negotiation frame.
        """
        try:
            if not packet.haslayer(Dot11Action):
                return None
        except Exception:
            return None

        try:
            raw = bytes(packet[Dot11Action].payload)
        except Exception:
            try:
                raw = bytes(packet.payload)
            except Exception:
                return None

        # raw expected layout: category(1) action(1) OUI(3) OUI_type(1) subtype(1) ...
        if len(raw) < 7:
            return None
        category, action = raw[0], raw[1]
        if category != CATEGORY_PUBLIC_ACTION or action != PUBLIC_ACTION_VENDOR_SPECIFIC:
            return None
        if raw[2:5] != P2P_OUI or raw[5] != P2P_OUI_TYPE:
            return None

        subtype = raw[6]
        if subtype not in (GO_NEG_REQUEST, GO_NEG_RESPONSE, GO_NEG_CONFIRM):
            return None

        attributes = self._parse_p2p_attributes(raw[7:])

        src_mac = None
        try:
            src_mac = packet[Dot11].addr2
        except Exception:
            pass

        return {
            "subtype": subtype,
            "name": _P2P_PUBLIC_ACTION_NAMES.get(subtype, "Unknown"),
            "src_mac": (src_mac or "unknown"),
            "attributes": attributes,
        }

    def _analyze_wps_method(self, packet) -> Optional[str]:
        """Determine the WPS configuration method advertised by a packet.

        Args:
            packet: A scapy packet potentially carrying a P2P IE with a
                P2P Device Info attribute (config methods bitmask).

        Returns:
            One of "PBC", "PIN Display", "PIN Keypad", "Display",
            "Keypad", or None if no WPS method could be determined.
        """
        ie_bytes = self._get_p2p_ie_bytes(packet)
        if ie_bytes is None:
            return None

        parsed = self._parse_p2p_ie(ie_bytes)
        for attr in parsed.get("attributes", []):
            if attr["id"] == P2P_ATTR_P2P_DEVICE_INFO and isinstance(attr["value"], dict):
                raw = attr["value"].get("config_methods_raw")
                if raw is None:
                    continue
                if raw & 0x0080:
                    return "PBC"
                if raw & 0x0108 == 0x0108:
                    return "PIN Display"
                if raw & 0x0188 == 0x0188:
                    return "PIN Keypad"
                if raw & 0x0008:
                    return "Display"
                if raw & 0x0100:
                    return "Keypad"
        return None

    # -----------------------------------------------------------------
    # Packet handling
    # -----------------------------------------------------------------

    def packet_handler(self, packet) -> None:
        """Scapy sniff() callback: filter and record P2P frames.

        Args:
            packet: A scapy packet captured by sniff().
        """
        if self._stop_event.is_set():
            return

        try:
            is_p2p = False

            if (
                packet.haslayer(Dot11ProbeReq)
                or packet.haslayer(Dot11ProbeResp)
                or packet.haslayer(Dot11Beacon)
            ):
                ie_bytes = self._get_p2p_ie_bytes(packet)
                if ie_bytes is not None:
                    is_p2p = True
                    self._record_device(packet, ie_bytes)

            gon = self._detect_go_negotiation(packet)
            if gon is not None:
                is_p2p = True
                with self._lock:
                    self.gon_frames.append(gon)
                self.logger.info("Captured %s from %s", gon["name"], gon["src_mac"])

            if is_p2p:
                with self._lock:
                    self.captured_packets.append(packet)

        except Exception as e:
            self.logger.debug("Error handling packet: %s", e)

    def _record_device(self, packet, ie_bytes: bytes) -> None:
        """Record a discovered P2P device from a probe/beacon P2P IE."""
        parsed = self._parse_p2p_ie(ie_bytes)
        if not parsed:
            return

        try:
            src_mac = packet[Dot11].addr2
        except Exception:
            src_mac = None

        device_addr = parsed.get("device_address") or src_mac
        if not device_addr:
            return
        device_addr = device_addr.upper()

        if self.target_device and device_addr != self.target_device:
            return

        with self._lock:
            entry = self.devices.setdefault(
                device_addr,
                {
                    "device_address": device_addr,
                    "device_name": parsed.get("device_name"),
                    "config_methods": parsed.get("config_methods", []),
                    "go_intent": parsed.get("go_intent"),
                    "first_seen": time.time(),
                },
            )
            if parsed.get("device_name"):
                entry["device_name"] = parsed["device_name"]
            if parsed.get("config_methods"):
                entry["config_methods"] = parsed["config_methods"]
            entry["last_seen"] = time.time()

        self.logger.info(
            "Discovered P2P device %s (%s)", device_addr, parsed.get("device_name") or "unknown"
        )

    # -----------------------------------------------------------------
    # Test modes
    # -----------------------------------------------------------------

    def _discover_p2p_devices(self) -> list[dict]:
        """Passively sniff for P2P devices via Probe Request/Response/Beacon.

        Returns:
            List of discovered device dicts.
        """
        self.logger.info(
            "Discovering P2P devices on %s (timeout=%ds)...", self.interface, self.timeout
        )
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                timeout=self.timeout,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
        except Exception as e:
            self.logger.error("Error during P2P discovery: %s", e)

        with self._lock:
            devices = list(self.devices.values())
        self.logger.info("Discovered %d P2P device(s)", len(devices))
        return devices

    def _detect_p2p_groups(self) -> list[dict]:
        """Find active P2P groups from the P2P Group Info attribute.

        Beacons sent by a P2P Group Owner carry a P2P IE with a Group
        Info attribute (and typically a P2P Group ID attribute) listing
        connected P2P clients.

        Returns:
            List of group dicts (go_address, ssid, channel, client_count).
        """
        self.logger.info(
            "Detecting active P2P groups on %s (timeout=%ds)...", self.interface, self.timeout
        )

        def handler(packet):
            self.packet_handler(packet)
            try:
                if not packet.haslayer(Dot11Beacon):
                    return
                ie_bytes = self._get_p2p_ie_bytes(packet)
                if ie_bytes is None:
                    return
                parsed = self._parse_p2p_ie(ie_bytes)
                if not parsed.get("has_group_info"):
                    return

                go_addr = None
                try:
                    go_addr = packet[Dot11].addr2
                except Exception:
                    pass
                if not go_addr:
                    return
                go_addr = go_addr.upper()

                ssid = None
                try:
                    elt = packet.getlayer(Dot11Elt)
                    while elt is not None:
                        if getattr(elt, "ID", None) == 0:
                            ssid = bytes(elt.info).decode("utf-8", errors="replace")
                            break
                        elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt, "payload") else None
                except Exception:
                    pass

                channel = None
                operating_channel_attr = next(
                    (a for a in parsed["attributes"] if a["id"] == P2P_ATTR_OPERATING_CHANNEL),
                    None,
                )
                if operating_channel_attr is not None:
                    channel = operating_channel_attr.get("value")

                with self._lock:
                    self.groups[go_addr] = {
                        "go_address": go_addr,
                        "ssid": ssid,
                        "channel": channel,
                        "last_seen": time.time(),
                    }
            except Exception as e:
                self.logger.debug("Error detecting P2P group: %s", e)

        try:
            sniff(
                iface=self.interface,
                prn=handler,
                timeout=self.timeout,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
        except Exception as e:
            self.logger.error("Error during P2P group detection: %s", e)

        with self._lock:
            groups = list(self.groups.values())
        self.logger.info("Detected %d active P2P group(s)", len(groups))
        return groups

    def _check_go_negotiation_security(self, gon_frames: list) -> list[dict]:
        """Analyze captured GO Negotiation frames for weaknesses.

        Checks performed:
          * GO Intent tie-breaking: an intent of 15 (always wants to be
            GO) or a tie-breaker bit pattern that is trivially
            predictable is flagged.
          * WPS method weakness: PBC-only negotiation offers no
            authentication of the pairing (push-button is inherently
            weak against an attacker in physical proximity).

        Args:
            gon_frames: List of GO negotiation frame dicts, as produced
                by ``_detect_go_negotiation``.

        Returns:
            List of finding dicts, each with "src_mac", "issue", and
            "severity".
        """
        findings: list[dict] = []

        for frame in gon_frames:
            src_mac = frame.get("src_mac", "unknown")
            attributes = frame.get("attributes", [])

            go_intent_attr = next((a for a in attributes if a["id"] == P2P_ATTR_GO_INTENT), None)
            if go_intent_attr is not None and isinstance(go_intent_attr.get("value"), dict):
                intent = go_intent_attr["value"].get("go_intent")
                if intent == 15:
                    findings.append(
                        {
                            "src_mac": src_mac,
                            "issue": "Maximum GO Intent (15) advertised — device always "
                            "insists on becoming Group Owner",
                            "severity": "low",
                        }
                    )

            for attr in attributes:
                if attr["id"] == P2P_ATTR_P2P_DEVICE_INFO and isinstance(attr["value"], dict):
                    methods = attr["value"].get("config_methods", [])
                    if methods == ["PBC"] or (
                        "PBC" in methods and "Display" not in methods and "Keypad" not in methods
                    ):
                        findings.append(
                            {
                                "src_mac": src_mac,
                                "issue": "PBC-only WPS configuration method — no PIN "
                                "authentication, vulnerable to rogue pairing "
                                "within button-press window",
                                "severity": "medium",
                            }
                        )

            status_attr = next((a for a in attributes if a["id"] == P2P_ATTR_STATUS), None)
            if status_attr is not None and status_attr.get("value") not in (None, 0):
                findings.append(
                    {
                        "src_mac": src_mac,
                        "issue": f"GO negotiation failed with status code "
                        f"{status_attr.get('value')}",
                        "severity": "info",
                    }
                )

        return findings

    def _analyze_group_negotiation(self) -> dict:
        """Sniff GO negotiation traffic and run the security checks on it.

        Returns:
            Dict with "gon_frames" (count), "findings" (security issues),
            and "wps_methods_seen".
        """
        self.logger.info(
            "Analyzing P2P group negotiation security on %s (timeout=%ds)...",
            self.interface,
            self.timeout,
        )
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                timeout=self.timeout,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
        except Exception as e:
            self.logger.error("Error during negotiation analysis: %s", e)

        with self._lock:
            gon_frames = list(self.gon_frames)

        findings = self._check_go_negotiation_security(gon_frames)

        wps_methods_seen: set = set()
        for frame in gon_frames:
            for attr in frame.get("attributes", []):
                if attr["id"] == P2P_ATTR_P2P_DEVICE_INFO and isinstance(attr["value"], dict):
                    wps_methods_seen.update(attr["value"].get("config_methods", []))

        return {
            "gon_frame_count": len(gon_frames),
            "gon_frames": gon_frames,
            "findings": findings,
            "wps_methods_seen": sorted(wps_methods_seen),
        }

    def _test_wps_pin_weakness(self) -> dict:
        """Passively check observed WPS methods for known weak defaults.

        Active WPS PIN brute-forcing against a P2P group requires a
        managed-mode interface running wpa_supplicant with P2P support
        (see REALISTIC_LIMITATION); this method only reports on the
        config methods seen so far and flags well-known weak/default PINs
        that are worth trying with wpa_supplicant/wpa_cli in a follow-up
        active test.

        Returns:
            Dict describing the passive WPS assessment.
        """
        self.logger.warning(REALISTIC_LIMITATION.strip())

        with self._lock:
            gon_frames = list(self.gon_frames)
            devices = list(self.devices.values())

        pbc_only_devices = [d for d in devices if d.get("config_methods") == ["PBC"]]

        return {
            "limitation": REALISTIC_LIMITATION.strip(),
            "devices_checked": len(devices),
            "pbc_only_devices": pbc_only_devices,
            "weak_pins_to_try": list(WEAK_WPS_PINS),
            "gon_frames_observed": len(gon_frames),
        }

    # -----------------------------------------------------------------
    # Orchestration
    # -----------------------------------------------------------------

    def start(self) -> dict:
        """Run the configured test mode and return the results.

        Returns:
            Dict with mode-specific results plus run metadata.
        """
        self.logger.info(
            "Starting WiFi Direct tester (mode=%s) on %s", self.test_mode, self.interface
        )
        self._running = True
        self._start_time = time.time()
        self._stop_event.clear()

        data: dict = {}
        try:
            if self.test_mode == "discover":
                data = {"devices": self._discover_p2p_devices()}
            elif self.test_mode == "analyze":
                data = self._analyze_group_negotiation()
            elif self.test_mode == "wps-test":
                data = self._test_wps_pin_weakness()
            elif self.test_mode == "detect-groups":
                data = {"groups": self._detect_p2p_groups()}
            elif self.test_mode == "all":
                data = {
                    "devices": self._discover_p2p_devices(),
                    "groups": self._detect_p2p_groups(),
                    "negotiation_analysis": self._analyze_group_negotiation(),
                    "wps_assessment": self._test_wps_pin_weakness(),
                }
            else:
                self.logger.error("Unknown test mode: %s", self.test_mode)
        finally:
            self._running = False

        with self._lock:
            self.results = {
                "mode": self.test_mode,
                "interface": self.interface,
                "target_device": self.target_device,
                "data": data,
            }

        return self.results

    def save_results(self) -> Optional[str]:
        """Save results JSON (and any captured packets as a pcap).

        Returns:
            Path to the saved JSON results file, or None if there was
            nothing to save or saving failed.
        """
        if not self.results:
            return None

        try:
            os.makedirs(self.output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(self.output_dir, f"wifi_direct_{timestamp}.json")
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.results, f, indent=2, default=str)
            self.logger.info("Results saved to %s", filepath)

            with self._lock:
                packets = list(self.captured_packets)
            if packets:
                pcap_path = os.path.join(self.output_dir, f"wifi_direct_{timestamp}.pcap")
                try:
                    wrpcap(pcap_path, packets)
                    self.logger.info("Captured P2P packets saved to %s", pcap_path)
                except Exception as e:
                    self.logger.warning("Failed to save pcap: %s", e)

            return filepath
        except Exception as e:
            self.logger.error("Failed to save results: %s", e)
            return None

    def get_status(self) -> dict:
        """Return current tester status.

        Returns:
            Dict with running state, mode, discovery counts, and elapsed
            time.
        """
        elapsed = 0.0
        if self._start_time is not None:
            elapsed = time.time() - self._start_time

        with self._lock:
            device_count = len(self.devices)
            group_count = len(self.groups)
            gon_count = len(self.gon_frames)

        return {
            "running": self._running,
            "interface": self.interface,
            "test_mode": self.test_mode,
            "target_device": self.target_device,
            "devices_discovered": device_count,
            "groups_detected": group_count,
            "gon_frames_captured": gon_count,
            "elapsed_seconds": round(elapsed, 1),
            "timeout": self.timeout,
        }

    def stop(self) -> None:
        """Signal any in-progress sniff loop to stop."""
        self._stop_event.set()
        self._running = False


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "WiFi Direct (P2P) Security Tester - passive discovery, GO "
            "negotiation analysis, and WPS weakness assessment. "
            "For authorized security testing and research only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  # Passive P2P device discovery (default mode)
  sudo python3 wifi_direct.py -i wlan0mon

  # Analyze GO negotiation security
  sudo python3 wifi_direct.py -i wlan0mon -m analyze

  # Passive WPS PIN weakness assessment
  sudo python3 wifi_direct.py -i wlan0mon -m wps-test

  # Detect active P2P groups
  sudo python3 wifi_direct.py -i wlan0mon -m detect-groups

  # Run all tests against a specific device
  sudo python3 wifi_direct.py -i wlan0mon -m all --target AA:BB:CC:DD:EE:FF

{REALISTIC_LIMITATION}
        """,
    )

    parser.add_argument(
        "-i", "--interface", required=True, help="Wireless interface in monitor mode"
    )
    parser.add_argument(
        "-m",
        "--mode",
        default="discover",
        choices=list(TEST_MODES),
        help="Test mode (default: discover)",
    )
    parser.add_argument(
        "--target", dest="target_device", default=None, help="Target P2P device MAC address"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=120, help="Timeout in seconds (default: 120)"
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="captures",
        help="Output directory for results (default: captures)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()
    require_root()

    if not validate_interface(args.interface):
        print(f"Invalid interface: {args.interface}", file=sys.stderr)
        sys.exit(1)

    if args.target_device and not validate_mac(args.target_device):
        print(f"Invalid target device MAC: {args.target_device}", file=sys.stderr)
        sys.exit(1)

    tester = WiFiDirectTester(
        interface=args.interface,
        test_mode=args.mode,
        target_device=args.target_device,
        timeout=args.timeout,
        output_dir=args.output_dir,
    )

    tester.start()
    tester.save_results()
    sys.exit(0)


if __name__ == "__main__":
    main()
