# Python-Hoover

A comprehensive WiFi security testing toolkit for Kali Linux and security-focused distributions. 28+ integrated tools covering reconnaissance, attack, defense, automation, and extensibility — all controllable from a web dashboard, REST API, or CLI.

## Tools

### Reconnaissance
| Tool | Description |
|------|-------------|
| `hoover` | Probe request monitor — capture device SSIDs with channel hopping, OUI vendor lookup, client fingerprinting, CSV/JSON/SQLite export |
| `ap-scanner` | Passive AP discovery — beacon/probe response capture, encryption detection (WEP/WPA/WPA2/WPA3/OWE), PMF, hidden SSID reveal, signal strength |
| `wardriving` | GPS-tagged AP mapping — gpsd integration, KML/CSV export, signal heatmapping |
| `ble-scanner` | Bluetooth Low Energy recon — device scanning, GATT service enumeration, RSSI filtering |
| `network-mapper` | Network discovery — ARP scan, port scan (top 100), banner grabbing, OS fingerprinting |

### Attack
| Tool | Description |
|------|-------------|
| `deauth` | Deauthentication — targeted or broadcast, continuous mode |
| `ssid-generator` | SSID broadcasting — beacon frames from text file |
| `ssid-capturer` | Rogue AP — hostapd access point with traffic capture, encryption, internet sharing |
| `handshake-capture` | WPA handshake — EAPOL 4-way capture + PMKID, handshake verification, .pcapng/.hccapx output for hashcat |
| `captive-portal` | Evil twin — fake login pages (hotel/airport/corporate), credential logging |
| `karma-attack` | Karma — auto-respond to all probe requests with matching beacons |
| `wps-attack` | WPS PIN brute force — Reaver/Bully/Pixie Dust wrapper |
| `packet-replay` | Packet replay — capture, filter, and replay WiFi frames from pcap |
| `eap-attack` | WPA-Enterprise — fake RADIUS/EAP server, credential capture (PEAP/TTLS/MD5) |
| `pmkid-capture` | PMKID extraction — clientless WPA attack, hashcat 22000 output |
| `mitm-attack` | MitM/ARP spoof — ARP cache poisoning, HTTP credential capture, DNS logging |
| `dragonblood` | WPA3/SAE testing — downgrade, timing side-channel, group negotiation attacks |
| `krack-detect` | KRACK detection — key reinstallation via EAPOL nonce reuse monitoring |
| `fragattacks` | FragAttacks — A-MSDU injection (CVE-2020-24588), mixed key fragments (CVE-2020-24587), fragment cache (CVE-2020-24586) |
| `wep-attack` | WEP cracking — IV collection, ARP replay, key recovery via aircrack-ng |
| `ble-attack` | BLE GATT attacks — service enumeration, characteristic read/write, notification flooding |

### Defense
| Tool | Description |
|------|-------------|
| `wids` | Wireless IDS — rogue AP, evil twin, deauth flood, karma detection, alerting |

### Automation & Infrastructure
| Tool | Description |
|------|-------------|
| `pentest-workflow` | Automated chain — scan → reveal hidden → fingerprint → target → deauth → capture → verify → WPS → dragonblood → KRACK → fragattacks → WEP → BLE → report |
| `hoover-web` | Web dashboard — control all tools from a browser with real-time monitoring |
| `hoover-api` | REST API — token-authenticated JSON API, rate limiting, programmatic tool control |
| `hoover-report` | Report generation — HTML/JSON/CSV security assessment reports |
| `multi-adapter` | Multi-adapter management — concurrent operations across multiple WiFi interfaces |
| `cloud-c2` | Cloud C2 — remote session management via Flask-SocketIO |
| `plugin-system` | Plugin architecture — extensible HooverPlugin base class with PluginManager |

## Requirements

- Python 3.9+
- Linux with wireless interface supporting monitor mode
- Root privileges

### System dependencies

```bash
sudo apt-get install hostapd dnsmasq tcpdump iptables aircrack-ng reaver
```

### Python dependencies

```bash
pip install scapy flask flask-socketio eventlet psutil          # core
pip install bleak                                                # BLE support
pip install reportlab                                            # PDF reports
pip install gpsd-py3                                             # GPS/wardriving
pip install cryptography                                         # C2 encryption
# Or install everything:
pip install ".[all]"
```

## Installation

```bash
git clone https://github.com/mrh4s/python-hoover.git
cd python-hoover
pip install -e .
```

This installs all 28+ tools as CLI commands.

## Quick Start

### Web Dashboard (recommended)

```bash
sudo hoover-web
# Open http://127.0.0.1:5000
# Password is printed to terminal on startup
```

### CLI — scan nearby APs

```bash
sudo ap-scanner -i wlan0mon -t 60 -o scan_results.json
```

### CLI — monitor probe requests

```bash
sudo hoover -i wlan0mon --channel-hop --output probes.csv
```

### CLI — automated pentest

```bash
sudo pentest-workflow -i wlan0mon -o pentest_results/ -v
```

## Tool Reference

### hoover — Probe Request Monitor

```bash
sudo hoover -i wlan0mon                          # basic monitoring
sudo hoover -i wlan0mon --output probes.csv      # save to CSV
sudo hoover -i wlan0mon --output probes.json     # save to JSON lines
sudo hoover -i wlan0mon --output probes.db       # save to SQLite
sudo hoover -i wlan0mon --json                   # JSON stdout
sudo hoover -i wlan0mon --channel 6 --no-hop     # fixed channel
sudo hoover -i wlan0mon --hop-interval 0.5       # slower hopping
sudo hoover -i wlan0mon --no-color               # no ANSI colors
sudo hoover -i wlan0mon --fingerprint            # client fingerprinting mode
sudo hoover -i wlan0mon --fingerprint --fp-output fps.json  # save fingerprints
```

#### Client Fingerprinting

When `--fingerprint` is passed, `hoover` extracts detailed client fingerprints from probe request Information Elements: supported rates, HT/VHT/HE capabilities, WPS data, power capability, and probed SSIDs. It uses these to guess the OS (iOS/Android/Windows/macOS/Linux) and device type (phone/laptop/tablet/IoT/AP). Save fingerprints with `--fp-output fingerprints.json`.

### ap-scanner — Passive AP Discovery

```bash
sudo ap-scanner -i wlan0mon                      # 30s scan
sudo ap-scanner -i wlan0mon -t 120               # 2 minute scan
sudo ap-scanner -i wlan0mon -ch 6 --no-hop       # fixed channel
sudo ap-scanner -i wlan0mon -o aps.json          # save results
sudo ap-scanner -i wlan0mon --hop-interval 1.0   # slower hopping
sudo ap-scanner -i wlan0mon --reveal-hidden      # reveal hidden SSIDs via directed probes
sudo ap-scanner -i wlan0mon --reveal-hidden --deauth-reveal  # deauth clients to reveal hidden SSIDs
```

### deauth — Deauthentication

```bash
sudo deauth -i wlan0mon -b AA:BB:CC:DD:EE:FF              # broadcast deauth (10 packets)
sudo deauth -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66  # targeted
sudo deauth -i wlan0mon -b AA:BB:CC:DD:EE:FF -n 50        # 50 packets
sudo deauth -i wlan0mon -b AA:BB:CC:DD:EE:FF --continuous  # continuous
sudo deauth -i wlan0mon -b AA:BB:CC:DD:EE:FF -d 0.5       # 0.5s delay between packets
sudo deauth -i wlan0mon -b AA:BB:CC:DD:EE:FF -ch 11       # set channel first
```

### handshake-capture — WPA Handshake + PMKID

```bash
sudo handshake-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF              # capture with auto-deauth
sudo handshake-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF --no-deauth  # passive capture
sudo handshake-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66  # target client
sudo handshake-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF -t 300       # 5 min timeout
sudo handshake-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF -ch 6        # set channel
sudo handshake-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF -o /tmp/caps # output directory
sudo handshake-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF --deauth-count 10 --deauth-interval 5.0
sudo handshake-capture --verify /path/to/capture.pcap        # verify a pcap file for complete handshake
sudo handshake-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF --verify-captured  # capture then verify
```

Output: `captures/handshake_<BSSID>_<timestamp>.pcapng` — use with `hashcat -m 22000` or `aircrack-ng`.

Verification checks: EAPOL 4-way message classification, nonce consistency, replay counter ordering, MIC presence.

### ssid-generator — SSID Broadcasting

```bash
sudo ssid-generator -i wlan0mon -f ssids.txt           # broadcast once
sudo ssid-generator -i wlan0mon -f ssids.txt -c        # continuous loop
sudo ssid-generator -i wlan0mon -f ssids.txt -t 0.5    # 0.5s interval
sudo ssid-generator -i wlan0mon -f ssids.txt -ch 11    # channel 11
python3 ssid_generator.py -f ssids.txt -l              # list SSIDs (no root)
```

### ssid-capturer — Rogue Access Point

```bash
sudo ssid-capturer -i wlan0 -f ssids.txt -s "Free-WiFi" -d 300        # open AP, 5 min
sudo ssid-capturer -i wlan0 -f ssids.txt -s "Hotel-WiFi" -e wpa2 -p "password123"  # WPA2
sudo ssid-capturer -i wlan0 -f ssids.txt -r -d 120                    # rotate SSIDs
sudo ssid-capturer -i wlan0 -f ssids.txt -s "Airport" --internet -u eth0  # NAT forwarding
```

### captive-portal — Evil Twin with Login Page

```bash
sudo captive-portal -i wlan0 -s "Hotel-Guest"                        # default template
sudo captive-portal -i wlan0 -s "Airport-WiFi" -t airport            # airport template
sudo captive-portal -i wlan0 -s "Corp-VPN" -t corporate              # corporate login
sudo captive-portal -i wlan0 -s "Cafe" -ch 11 -o creds.log           # custom output
sudo captive-portal -i wlan0 -s "Free" --bind 10.0.0.1               # custom gateway IP
```

Templates: `default`, `hotel`, `airport`, `corporate`. Credentials saved to `captures/portal_creds.log`.

### karma-attack — Auto Probe Response

```bash
sudo karma-attack -i wlan0mon                                         # respond to all probes
sudo karma-attack -i wlan0mon --whitelist AA:BB:CC:DD:EE:FF           # target specific MAC
sudo karma-attack -i wlan0mon --blacklist 11:22:33:44:55:66           # exclude MAC
sudo karma-attack -i wlan0mon --bssid DE:AD:BE:EF:00:01              # custom BSSID
sudo karma-attack -i wlan0mon -ch 6 -o karma.log                     # fixed channel + log
```

### wids — Wireless Intrusion Detection

```bash
sudo wids -i wlan0mon                                                 # monitor with defaults
sudo wids -i wlan0mon --known-aps known.json                         # compare against whitelist
sudo wids -i wlan0mon --deauth-threshold 20 --deauth-window 10       # custom flood detection
sudo wids -i wlan0mon -o alerts.json                                  # save alerts to JSON
```

Detects: rogue APs, evil twins, deauth floods, karma attacks, EAPOL anomalies.

### packet-replay — Capture and Replay

```bash
sudo packet-replay -i wlan0mon -w capture.pcap -t 60                 # capture 60s to file
sudo packet-replay -i wlan0mon -r capture.pcap                       # replay once
sudo packet-replay -i wlan0mon -r capture.pcap -c 5 -d 0.5           # replay 5x, 0.5s delay
sudo packet-replay -i wlan0mon -r capture.pcap --filter beacon        # replay only beacons
sudo packet-replay -i wlan0mon -r capture.pcap --filter-mac AA:BB:CC:DD:EE:FF
```

Filter types: `beacon`, `probe`, `deauth`, `eapol`, `all`.

### wps-attack — WPS PIN Brute Force

```bash
sudo wps-attack -i wlan0mon -b AA:BB:CC:DD:EE:FF                     # reaver (default)
sudo wps-attack -i wlan0mon -b AA:BB:CC:DD:EE:FF -m bully            # bully
sudo wps-attack -i wlan0mon -b AA:BB:CC:DD:EE:FF -m pixie-dust       # pixie dust
sudo wps-attack -i wlan0mon -b AA:BB:CC:DD:EE:FF --pin 12345670      # known PIN
sudo wps-attack -i wlan0mon -b AA:BB:CC:DD:EE:FF -t 600 -ch 6       # 10 min timeout
```

Requires `reaver` or `bully` installed.

### network-mapper — ARP Scan + Port Discovery

```bash
sudo network-mapper -i wlan0                                          # scan 192.168.1.0/24
sudo network-mapper -i wlan0 -r 10.0.0.0/24                          # custom range
sudo network-mapper -i wlan0 --no-port-scan                           # ARP only
sudo network-mapper -i wlan0 -p 22,80,443,8080                       # custom ports
sudo network-mapper -i wlan0 -t 5.0 -o network.json                  # 5s timeout, save
```

### ble-scanner — BLE Reconnaissance

```bash
ble-scanner                                                           # 10s scan
ble-scanner -t 30                                                     # 30s scan
ble-scanner --services                                                # enumerate GATT services
ble-scanner --filter-name "iPhone"                                    # filter by name
ble-scanner --filter-rssi -60                                         # minimum signal strength
ble-scanner -o devices.json                                           # save results
```

No root needed for BLE. Requires `bleak` Python package.

### pentest-workflow — Automated Assessment

```bash
sudo pentest-workflow -i wlan0mon                                     # basic workflow
sudo pentest-workflow -i wlan0mon --full-auto                         # run ALL applicable tests
sudo pentest-workflow -i wlan0mon -b AA:BB:CC:DD:EE:FF               # target specific AP
sudo pentest-workflow -i wlan0mon --no-deauth                         # passive only
sudo pentest-workflow -i wlan0mon --skip-wps                          # skip WPS testing
sudo pentest-workflow -i wlan0mon -t 600 -o results/                 # 10 min, custom output

# Individual test toggles
sudo pentest-workflow -i wlan0mon --reveal-hidden                     # reveal hidden SSIDs
sudo pentest-workflow -i wlan0mon --fingerprint                       # client fingerprinting
sudo pentest-workflow -i wlan0mon --no-verify                         # skip handshake verification
sudo pentest-workflow -i wlan0mon --dragonblood                       # WPA3/SAE vulnerability testing
sudo pentest-workflow -i wlan0mon --krack                             # KRACK detection
sudo pentest-workflow -i wlan0mon --fragattacks                       # FragAttacks testing
sudo pentest-workflow -i wlan0mon --wep                               # WEP attack for WEP targets
sudo pentest-workflow -i wlan0mon --ble                               # BLE device scanning
sudo pentest-workflow -i wlan0mon --wardriving --gpsd-host 127.0.0.1 --gpsd-port 2947

# Report and plugin options
sudo pentest-workflow -i wlan0mon --report-format html                # HTML report (json/html/pdf/all)
sudo pentest-workflow -i wlan0mon --plugins-dir ./plugins             # load plugins
sudo pentest-workflow -i wlan0mon --adapters '[{"interface":"wlan1mon","role":"inject"}]'
```

Workflow phases (in order): scan APs → reveal hidden SSIDs → fingerprint clients → select target → deauth clients → capture handshake → verify handshake → WPS check → Dragonblood WPA3 test → KRACK detection → FragAttacks → WEP attack → BLE scan → generate report. Each phase is skipped when its flag is not set (unless `--full-auto` enables all). The workflow is also controllable from the web dashboard via `/api/pentest-workflow/start`.

### eap-attack — WPA-Enterprise EAP Testing

```bash
sudo eap-attack -i wlan0 -s "Corp-WiFi"                               # PEAP (default)
sudo eap-attack -i wlan0 -s "Eduroam" -m ttls                         # EAP-TTLS
sudo eap-attack -i wlan0 -s "Office" -m md5                           # EAP-MD5
sudo eap-attack -i wlan0 -s "Corp" -ch 11 -t 600                      # channel 11, 10 min
sudo eap-attack -i wlan0 -s "Corp" -o /tmp/creds                      # custom output dir
```

Creates a rogue WPA-Enterprise AP using hostapd's integrated EAP server. Captures EAP identities, MSCHAPv2 challenge/response pairs, and MD5 challenges. Credentials saved to JSON in output directory. Methods: `peap`, `ttls`, `md5`.

### pmkid-capture — Clientless PMKID Extraction

```bash
sudo pmkid-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF                   # capture PMKID
sudo pmkid-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF -ch 6             # set channel
sudo pmkid-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF -t 30             # 30s timeout
sudo pmkid-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF --client-mac 11:22:33:44:55:66
sudo pmkid-capture -i wlan0mon -b AA:BB:CC:DD:EE:FF -o /tmp/caps      # custom output
```

Extracts PMKID from EAPOL Key message 1 without requiring connected clients. Sends association request to trigger the AP's response, then parses the PMKID KDE. Output: hashcat 22000 format (`WPA*02*<PMKID>*<AP_MAC>*<STA_MAC>*<ESSID_hex>***`). Use with `hashcat -m 22000`.

### mitm-attack — MitM / ARP Spoofing

```bash
sudo mitm-attack -i eth0 --target 192.168.1.100 --gateway 192.168.1.1          # basic MitM
sudo mitm-attack -i wlan0 --target 192.168.1.50 --gateway 192.168.1.1 -t 600   # 10 min
sudo mitm-attack -i eth0 --target 10.0.0.5 --gateway 10.0.0.1 --no-forward     # no IP forwarding
sudo mitm-attack -i eth0 --target 192.168.1.100 --gateway 192.168.1.1 -p 80,443,8080
sudo mitm-attack -i eth0 --target 192.168.1.100 --gateway 192.168.1.1 -o /tmp/mitm
```

ARP cache poisoning with IP forwarding, HTTP credential extraction (POST data with username/password fields), and DNS query logging. Automatically restores ARP tables on stop. Default capture ports: `80,8080,443,21,25,110,143`. Captured data saved to JSON.

### ble-attack — BLE GATT Attacks

```bash
ble-attack -m scan -t 15                                              # scan for BLE devices
ble-attack -m enumerate --target AA:BB:CC:DD:EE:FF                     # full GATT enumeration
ble-attack -m replay --target AA:BB:CC:DD:EE:FF \
    --uuid 0000ffe1-0000-1000-8000-00805f9b34fb --write-data deadbeef \
    --replay-count 20 --replay-interval 0.2                           # replay a captured write
ble-attack -m fuzz --target AA:BB:CC:DD:EE:FF \
    --uuid 0000ffe1-0000-1000-8000-00805f9b34fb                       # fuzz a characteristic
ble-attack -m spoof --spoof-name "Fake Device"                        # spoof advertisement (BlueZ)
```

GATT service/characteristic/descriptor enumeration, characteristic read/write, write replay, notification capture, and characteristic fuzzing (zeros, 0xFF, incrementing bytes, oversized data, format strings) via `bleak`. Advertisement spoofing uses `hcitool`/`hciconfig` and is limited by BlueZ/hardware support; full raw BLE packet injection requires specialized hardware (Ubertooth, nRF52840). No root required for most operations. Results saved to JSON. Requires `bleak` Python package.

### hoover-api — REST API

```bash
hoover-api --host 127.0.0.1 --port 8080                    # starts, prints an auto-generated token
hoover-api --token mysecrettoken123                        # use a fixed token
hoover-api --cors-origins http://localhost:3000             # enable CORS for a dashboard origin
hoover-api --no-auth                                        # DANGEROUS: disables authentication
```

A token-authenticated JSON REST API (separate from the `hoover-web` HTML GUI) for driving the toolkit programmatically. Tool instances run in-process (daemon threads), not as subprocesses. All requests except where noted require an `Authorization: Bearer <token>` header, and are rate-limited to 60 requests/minute per IP.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/status` | Overall system status |
| GET | `/api/v1/interfaces` | List wireless interfaces |
| GET | `/api/v1/tools` | List all tools and their status |
| POST | `/api/v1/tools/{tool}/start` | Start a tool with a JSON body of its constructor params |
| POST | `/api/v1/tools/{tool}/stop` | Stop a running tool |
| GET | `/api/v1/tools/{tool}/status` | Get status of a specific tool |
| GET | `/api/v1/captures` | List capture files |
| GET | `/api/v1/captures/{filename}` | Download a capture file |
| GET | `/api/v1/results/{tool}` | Get results/data from a tool run |
| POST | `/api/v1/scan/ap` | Start an AP scan, return results when done |
| POST | `/api/v1/scan/clients` | Start a client probe scan |
| GET | `/api/v1/fingerprints` | Get client fingerprints |
| POST | `/api/v1/handshake/capture` | Start a handshake capture |
| POST | `/api/v1/handshake/verify` | Verify a captured handshake file |
| POST | `/api/v1/attack/{type}` | Start an attack (`deauth`, `karma`, `pmkid`, `eap`, `mitm`, `wps`) |
| GET | `/api/v1/reports` | List generated reports |
| POST | `/api/v1/reports/generate` | Generate a report from results |

Responses are always JSON: `{"success": true, "data": {...}}` on success, or `{"success": false, "error": "message", "code": "ERROR_CODE"}` on failure. Long-running tools return a `task_id`; poll `/api/v1/tools/{tool}/status` for completion. **Authorized pentest use only** — bind to `127.0.0.1` and keep authentication enabled unless you have a specific, authorized reason to expose this more broadly.

### dragonblood — WPA3/SAE Testing

```bash
sudo dragonblood -i wlan0mon -b AA:BB:CC:DD:EE:FF              # run all tests
sudo dragonblood -i wlan0mon -b AA:BB:CC:DD:EE:FF --mode downgrade  # downgrade attack only
sudo dragonblood -i wlan0mon -b AA:BB:CC:DD:EE:FF --mode timing     # timing side-channel
sudo dragonblood -i wlan0mon -b AA:BB:CC:DD:EE:FF --mode group      # group negotiation
```

Tests WPA3/SAE networks for Dragonblood vulnerabilities: SAE downgrade to WPA2, timing side-channel leaks, and weak group negotiation.

### krack-detect — Key Reinstallation Detection

```bash
sudo krack-detect -i wlan0mon                                   # monitor all traffic
sudo krack-detect -i wlan0mon -b AA:BB:CC:DD:EE:FF              # monitor specific AP
sudo krack-detect -i wlan0mon --timeout 300                      # 5-minute capture
```

Monitors EAPOL frames to detect key reinstallation attacks by tracking nonce reuse across the 4-way handshake.

### fragattacks — Frame Fragmentation Testing

```bash
sudo fragattacks -i wlan0mon -b AA:BB:CC:DD:EE:FF               # all tests
sudo fragattacks -i wlan0mon -b AA:BB:CC:DD:EE:FF --mode amsdu  # CVE-2020-24588
sudo fragattacks -i wlan0mon -b AA:BB:CC:DD:EE:FF --mode mixed-key  # CVE-2020-24587
sudo fragattacks -i wlan0mon -b AA:BB:CC:DD:EE:FF --mode cache  # CVE-2020-24586
```

Tests for FragAttacks (fragmentation and aggregation) vulnerabilities: A-MSDU injection, mixed key fragment attack, and fragment cache poisoning.

### wep-attack — WEP Key Recovery

```bash
sudo wep-attack -i wlan0mon -b AA:BB:CC:DD:EE:FF                # collect IVs + crack
sudo wep-attack -i wlan0mon -b AA:BB:CC:DD:EE:FF --arp-replay   # active ARP replay
sudo wep-attack -i wlan0mon -b AA:BB:CC:DD:EE:FF --min-ivs 50000  # min IVs before crack
```

Collects WEP initialization vectors via passive capture or active ARP replay, then recovers the key using aircrack-ng.

### wardriving — GPS-Tagged AP Mapping

```bash
sudo wardriving -i wlan0mon                                      # scan with gpsd
sudo wardriving -i wlan0mon -o wardrive_results.csv              # CSV output
sudo wardriving -i wlan0mon --export-kml map.kml                 # KML for Google Earth
```

Combines AP scanning with GPS coordinates from gpsd for wardriving. Exports to CSV or KML for mapping and analysis.

### cloud-c2 — Remote Command & Control

```bash
sudo cloud-c2 --port 8443                                       # start C2 server
sudo cloud-c2 --port 8443 --secret mysecret                     # with shared secret
```

Flask-SocketIO-based remote session management for controlling Hoover agents from a central server. Restricted command execution (no arbitrary shell).

### multi-adapter — Multi-Adapter Management

```bash
sudo multi-adapter --adapters wlan0mon,wlan1mon                  # manage multiple adapters
sudo multi-adapter --adapters wlan0mon,wlan1mon --task scan      # parallel scanning
```

Manages concurrent operations across multiple WiFi adapters with thread-safe task scheduling.

### hoover-report — Report Generation

```bash
hoover-report -i results.json -o report.html --format html      # HTML report
hoover-report -i results.json -o report.json --format json       # JSON report
hoover-report -i results.json -o report.csv --format csv         # CSV report
```

Generates security assessment reports from scan results in HTML, JSON, or CSV format.

## Monitor Mode Setup

```bash
# Using airmon-ng
sudo airmon-ng check kill
sudo airmon-ng start wlan0
# Interface becomes wlan0mon

# Or use the included helper
sudo ./setup_interface.sh monitor wlan0

# Return to managed mode
sudo ./setup_interface.sh managed wlan0mon
```

## Testing

```bash
pip install pytest pytest-cov
python -m pytest tests/ -v          # 785 tests, no root/hardware needed
python -m pytest tests/ --cov       # with coverage report
```

## Project Structure

```
python-hoover/
├── hoover.py              # Probe request monitor
├── ap_scanner.py          # Passive AP scanner
├── deauth.py              # Deauthentication
├── handshake_capture.py   # WPA handshake capture
├── ssid_generator.py      # SSID broadcasting
├── ssid_capturer.py       # Rogue AP
├── captive_portal.py      # Evil twin captive portal
├── karma_attack.py        # Karma attack
├── wids.py                # Wireless IDS
├── packet_replay.py       # Packet replay
├── wps_attack.py          # WPS attack
├── network_mapper.py      # Network mapper
├── ble_scanner.py         # BLE scanner
├── pentest_workflow.py    # Automated workflow
├── eap_attack.py          # WPA-Enterprise EAP attack
├── pmkid_capture.py       # PMKID clientless capture
├── mitm_attack.py         # MitM/ARP spoofing
├── dragonblood.py         # WPA3/SAE Dragonblood testing
├── krack.py               # KRACK detection
├── fragattacks.py         # FragAttacks vulnerability testing
├── multi_adapter.py       # Multi-adapter management
├── rest_api.py            # REST API server
├── reporting.py           # Report generation (HTML/JSON/CSV)
├── plugin_system.py       # Plugin architecture
├── wardriving.py          # GPS/wardriving
├── cloud_c2.py            # Cloud C2 server
├── wep_attack.py          # WEP attack
├── ble_attack.py          # BLE GATT attacks
├── hoover_web.py          # Web dashboard
├── utils.py               # Shared utilities
├── oui_lookup.py          # MAC vendor lookup
├── templates/             # Web GUI HTML
├── static/                # CSS + JS
├── tests/                 # 785 pytest tests
├── ssid_files/            # SSID list files
├── captures/              # Output directory
├── pyproject.toml         # Project config + entry points
└── requirements.txt       # Python dependencies
```

## Legal Notice

This toolkit is for **authorized security testing, research, and education only**. Users must:

- Obtain proper authorization before testing any networks
- Comply with all applicable local laws and regulations
- Use only on networks they own or have explicit written permission to test

Unauthorized use may violate the Computer Fraud and Abuse Act (US) and similar legislation worldwide.

## License

See LICENSE file for details.
