#!/bin/sh

iptables -C FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null \
  || iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

cmake -S /spider -B /tmp/build && cmake --build /tmp/build && /tmp/build/spider eth0

sleep infinity