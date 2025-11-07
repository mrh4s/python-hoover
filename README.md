# python-hoover
Hoover is a powerful WiFi probe request monitoring tool for Kali Linux and other security-focused distributions. It captures and analyzes probe requests sent by nearby wireless devices, revealing the SSIDs (network names) they're searching for.

## Features

- **Probe Request Monitoring** (`hoover.py`): Captures and displays WiFi probe requests from nearby devices
- **SSID Generator** (`ssid_generator.py`): Broadcasts custom SSIDs from a text file for testing and research

## Requirements

- Python 3.x
- Scapy (`pip install scapy`)
- Wireless interface capable of monitor mode
- Root/sudo privileges
- Linux-based system (tested on Kali Linux)

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

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

See LICENSE file for details.
