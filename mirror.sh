#!/bin/sh
set -e

CLIENTS="client1 client2"

host_veth() {
    idx=$(docker compose exec -T "$1" cat /sys/class/net/"$2"/iflink)
    ip -o link | awk -F'[:@ ]+' -v i="$idx" '$1 == i {print $2}'
}

LAN_IFACE=$(docker compose exec -T router ip -o -4 addr show | awk '/10\.0\.1\.254/ {print $2}')
ROUTER_VETH=$(host_veth router "$LAN_IFACE")
ROUTER_MAC=$(docker compose exec -T router cat /sys/class/net/"$LAN_IFACE"/address)

for c in $CLIENTS; do
    v=$(host_veth "$c" eth0)
    tc qdisc del dev "$v" clsact 2>/dev/null || true
    tc qdisc add dev "$v" clsact
    tc filter add dev "$v" ingress prio 1 flower dst_mac "$ROUTER_MAC" action ok
    tc filter add dev "$v" ingress prio 2 flower dst_mac ff:ff:ff:ff:ff:ff action ok
    tc filter add dev "$v" ingress prio 3 matchall action mirred egress mirror dev "$ROUTER_VETH"
    echo "mirroring $c ($v) -> router $LAN_IFACE ($ROUTER_VETH)"
done