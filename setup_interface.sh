#!/bin/bash
# Helper script to setup wireless interface for Hoover tools
# Sets up monitor mode or managed mode as needed

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 [monitor|managed] <interface>"
    echo ""
    echo "Examples:"
    echo "  $0 monitor wlan0    # Enable monitor mode (for hoover.py, ssid_generator.py)"
    echo "  $0 managed wlan0mon # Return to managed mode"
    echo ""
}

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root (use sudo)${NC}"
    exit 1
fi

if [ "$#" -ne 2 ]; then
    print_usage
    exit 1
fi

MODE=$1
INTERFACE=$2

case $MODE in
    monitor)
        echo -e "${GREEN}[+] Enabling monitor mode on $INTERFACE${NC}"

        # Check if airmon-ng is available
        if command -v airmon-ng &> /dev/null; then
            echo "[*] Using airmon-ng..."
            airmon-ng check kill
            airmon-ng start $INTERFACE

            # Find the monitor interface name
            MON_INTERFACE="${INTERFACE}mon"
            if iwconfig $MON_INTERFACE 2>/dev/null | grep -q "Mode:Monitor"; then
                echo -e "${GREEN}[+] Monitor mode enabled: $MON_INTERFACE${NC}"
                echo "[*] Use this interface name with the Hoover tools"
            fi
        else
            # Manual method
            echo "[*] Using manual method (airmon-ng not found)..."
            ip link set $INTERFACE down
            iw dev $INTERFACE set type monitor
            ip link set $INTERFACE up

            if iwconfig $INTERFACE 2>/dev/null | grep -q "Mode:Monitor"; then
                echo -e "${GREEN}[+] Monitor mode enabled on $INTERFACE${NC}"
            else
                echo -e "${RED}[!] Failed to enable monitor mode${NC}"
                exit 1
            fi
        fi
        ;;

    managed)
        echo -e "${GREEN}[+] Returning $INTERFACE to managed mode${NC}"

        if command -v airmon-ng &> /dev/null; then
            echo "[*] Using airmon-ng..."
            airmon-ng stop $INTERFACE
        else
            echo "[*] Using manual method..."
            ip link set $INTERFACE down
            iw dev $INTERFACE set type managed
            ip link set $INTERFACE up
        fi

        # Restart NetworkManager if available
        if systemctl is-active --quiet NetworkManager; then
            echo "[*] Restarting NetworkManager..."
            systemctl restart NetworkManager
        fi

        echo -e "${GREEN}[+] Interface returned to managed mode${NC}"
        ;;

    *)
        echo -e "${RED}[!] Invalid mode: $MODE${NC}"
        print_usage
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}[+] Current interface status:${NC}"
iwconfig $INTERFACE 2>/dev/null || echo "Interface $INTERFACE not found"
if [ -e "/sys/class/net/${INTERFACE}mon" ]; then
    iwconfig ${INTERFACE}mon 2>/dev/null
fi
