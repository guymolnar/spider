FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        tcpdump \
        iptables \
        build-essential \
        cmake \
        pkg-config \
        libnetfilter-queue-dev \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
