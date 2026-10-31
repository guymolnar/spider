from scapy.all import IP, ICMP, send
ip = "172.25.96.1" #my pc's ip

send(IP(dst=ip)/ICMP(), loop=1, inter=0)