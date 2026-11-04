from scapy.all import IP, ICMP, send
ip = "10.0.2.10"

send(IP(dst=ip)/ICMP(), loop=1, inter=0)