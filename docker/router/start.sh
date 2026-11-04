#!/bin/sh

iptables -C FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null \
  || iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

cmake -S /spider -B /build && cmake --build /build
sleep infinity