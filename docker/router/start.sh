#!/bin/sh

iptables -C FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null \
  || iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass

cmake -S /spider -B /spider/build && cmake --build /spider/build && /spider/build/spider

sleep infinity