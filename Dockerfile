FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    aircrack-ng \
    hashcat \
    hostapd \
    dnsmasq \
    iw \
    wireless-tools \
    hcxtools \
    reaver \
    gpsd \
    gpsd-clients \
    bluez \
    bluetooth \
    iproute2 \
    iptables \
    net-tools \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/hoover

COPY . .

RUN pip install --break-system-packages -e ".[all]"

EXPOSE 5000 8443

ENTRYPOINT ["/bin/bash"]
