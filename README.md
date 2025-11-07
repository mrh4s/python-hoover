# python-hoover
Hoover is a powerful WiFi probe request monitoring tool for Kali Linux and other security-focused distributions. It captures and analyzes probe requests sent by nearby wireless devices, revealing the SSIDs (network names) they're searching for.

## Features

- **Probe Request Monitoring** (`hoover.py`): Captures and displays WiFi probe requests from nearby devices
- **SSID Generator** (`ssid_generator.py`): Broadcasts custom SSIDs from a text file for testing and research
- **SSID Capturer** (`ssid_capturer.py`): Creates rogue access points and captures traffic from connecting clients

## Requirements

### Basic Requirements (all tools)
- Python 3.x
- Scapy (`pip install scapy`)
- Wireless interface capable of monitor mode
- Root/sudo privileges
- Linux-based system (tested on Kali Linux)

### Additional Requirements (for SSID Capturer)
- hostapd (access point daemon)
- dnsmasq (DHCP server)
- tcpdump (packet capture)
- iptables (for internet sharing)

Install on Debian/Ubuntu/Kali:
```bash
sudo apt-get install hostapd dnsmasq tcpdump iptables
```

## Installation

```bash
git clone https://github.com/yourusername/python-hoover.git
cd python-hoover
pip install scapy
```

## Usage

### Hoover - Probe Request Monitor

Monitor WiFi probe requests from nearby devices:

```bash
# Enable monitor mode on your interface
sudo airmon-ng start wlan0

# Run Hoover
sudo python3 hoover.py -i wlan0mon

# Run with verbose output
sudo python3 hoover.py -i wlan0mon -v
```

### SSID Generator Add-on

Broadcast SSIDs from a text file to a wireless interface:

```bash
# List SSIDs in file (no root required)
python3 ssid_generator.py -f example_ssids.txt -l

# Broadcast SSIDs once
sudo python3 ssid_generator.py -i wlan0mon -f example_ssids.txt

# Continuously broadcast SSIDs
sudo python3 ssid_generator.py -i wlan0mon -f example_ssids.txt -c

# Custom interval and channel
sudo python3 ssid_generator.py -i wlan0mon -f example_ssids.txt -t 0.5 -ch 11
```

#### SSID File Format

Create a text file with one SSID per line:

```
# Comments start with #
CoffeeShop-WiFi
Hotel-Guest
Airport-Free-WiFi
Corporate-Network
```

See `example_ssids.txt` for a complete example.

#### SSID Generator Options

- `-i, --interface`: Wireless interface in monitor mode (required for broadcasting)
- `-f, --file`: Text file containing SSIDs (required)
- `-c, --continuous`: Continuously broadcast SSIDs in a loop
- `-t, --interval`: Time interval between frames in seconds (default: 0.1)
- `-ch, --channel`: WiFi channel to use (default: 6)
- `-l, --list`: List SSIDs from file without broadcasting

### SSID Capturer - Rogue Access Point with Traffic Capture

Create fake access points from your SSID list and capture all traffic from connecting clients:

```bash
# Setup helper (optional - enables monitor mode)
sudo ./setup_interface.sh monitor wlan0

# Single open SSID for 5 minutes
sudo python3 ssid_capturer.py -i wlan0 -f example_ssids.txt -s "Free-WiFi" -d 300

# WPA2 protected SSID
sudo python3 ssid_capturer.py -i wlan0 -f example_ssids.txt -s "CoffeeShop-WiFi" \
    -e wpa2 -p "password123" -d 600

# Rotate through all SSIDs (2 minutes each)
sudo python3 ssid_capturer.py -i wlan0 -f example_ssids.txt -r -d 120

# With internet sharing (requires upstream connection)
sudo python3 ssid_capturer.py -i wlan0 -f example_ssids.txt -s "Airport-WiFi" \
    --internet -u eth0 -d 600

# Return interface to normal mode when done
sudo ./setup_interface.sh managed wlan0
```

#### SSID Capturer Features

- **Rogue Access Point**: Creates real WiFi access points using hostapd
- **Traffic Capture**: Records all packets to .pcap files using tcpdump
- **Client Logging**: Tracks connected clients with MAC/IP addresses
- **Encryption Support**: Open networks, WPA2, or WEP
- **Internet Sharing**: Optional NAT forwarding to upstream interface
- **SSID Rotation**: Cycle through multiple SSIDs automatically
- **Detailed Logging**: Timestamps and connection information

#### SSID Capturer Options

- `-i, --interface`: Wireless interface (will be auto-configured)
- `-f, --file`: Text file containing SSIDs (required)
- `-s, --ssid`: Specific SSID to use (required if not using -r)
- `-r, --rotate`: Rotate through all SSIDs in file
- `-d, --duration`: Duration in seconds (per SSID if rotating, default: 300)
- `-o, --output`: Output directory for captures (default: ./captures)
- `-ch, --channel`: WiFi channel (default: 6)
- `-e, --encryption`: Encryption type: wpa2, wep (default: open)
- `-p, --password`: Password for encrypted network
- `--internet`: Enable internet sharing (requires -u)
- `-u, --upstream`: Upstream interface for internet (e.g., eth0, ppp0)

#### Captured Data

All data is saved to the output directory (default: `./captures/`):

- `capture_<ssid>_<timestamp>.pcap` - Full packet capture (analyze with Wireshark)
- `capture_log.txt` - Timestamped activity log
- `connected_clients.txt` - List of all clients that connected
- `hostapd.conf` - Configuration used for access point
- `dnsmasq.conf` - DHCP server configuration

#### Analyzing Captured Data

```bash
# View captures with Wireshark
wireshark captures/capture_Free-WiFi_*.pcap

# Extract credentials from captures (requires additional tools)
# Example with tshark:
tshark -r captures/capture_*.pcap -Y "http.request.method == POST" -T fields \
    -e http.request.uri -e http.file_data

# View connected clients
cat captures/connected_clients.txt

# View activity log
cat captures/capture_log.txt
```

## Use Cases

### Authorized Security Testing
- Penetration testing of wireless security systems
- Testing device behavior and probe request patterns
- Evaluating WiFi tracking prevention mechanisms

### Research and Education
- Studying WiFi protocol behavior
- Demonstrating wireless security concepts
- Academic research on wireless privacy

### Testing
- Testing custom wireless applications
- Validating WiFi detection systems
- Network security tool development

## Legal Notice

This tool is designed for authorized security testing, research, and educational purposes only. Users must:

- Obtain proper authorization before testing any networks
- Comply with local laws and regulations
- Use only on networks you own or have explicit permission to test
- Not use for malicious purposes or unauthorized access

Unauthorized use of this tool may violate laws including the Computer Fraud and Abuse Act (US) and similar legislation in other jurisdictions.

## How It Works

### Probe Request Monitoring
When devices search for WiFi networks, they send probe requests containing SSIDs of networks they've previously connected to. Hoover captures these requests to reveal what networks devices are looking for.

### SSID Broadcasting
The SSID generator creates beacon frames (the packets access points use to advertise their presence) with custom SSIDs from your text file. This can be used to test how devices respond to specific network names.

### Traffic Capture (Rogue AP)
The SSID capturer creates a fully functional access point using hostapd. When clients connect:
1. **Association**: Client associates with the fake access point
2. **DHCP**: dnsmasq assigns an IP address to the client
3. **Capture**: tcpdump records all network traffic to/from the client
4. **Logging**: Client information (MAC, IP) is logged with timestamps
5. **Optional Internet**: Traffic can be forwarded to an upstream interface (MITM)

All captured traffic is saved as .pcap files for analysis with tools like Wireshark or tshark.

## Troubleshooting

### Interface not in monitor mode
```bash
# Enable monitor mode
sudo airmon-ng start wlan0

# Check monitor mode
iwconfig wlan0mon
```

### Permission denied
Make sure to run with sudo:
```bash
sudo python3 hoover.py -i wlan0mon
sudo python3 ssid_generator.py -i wlan0mon -f ssids.txt
```

### No packets captured
- Verify monitor mode is enabled
- Check that you're using the correct interface name
- Ensure wireless drivers support monitor mode
- Try a different channel

### Hostapd fails to start (SSID Capturer)
```bash
# Check if interface is in use
sudo airmon-ng check kill

# Verify interface supports AP mode
iw list | grep -A 10 "Supported interface modes"

# Try a different channel
sudo python3 ssid_capturer.py -i wlan0 -f ssids.txt -s "Test" -ch 11
```

### No clients connecting (SSID Capturer)
- Ensure the SSID matches one devices are looking for
- Try using an open network (no encryption) first
- Check that the channel is correct for your region
- Verify the wireless interface supports AP mode
- Test with your own device first

### Internet sharing not working
```bash
# Verify upstream interface has internet
ping -I eth0 8.8.8.8

# Check iptables rules
sudo iptables -t nat -L -n -v

# Ensure IP forwarding is enabled
sudo sysctl net.ipv4.ip_forward
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

See LICENSE file for details.
