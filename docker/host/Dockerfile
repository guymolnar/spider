FROM debian:bookworm-slim


RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        iputils-ping \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*
