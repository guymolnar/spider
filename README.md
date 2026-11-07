# S.P.I.D.E.R
Stateful Packet Inspection & Defensive Engine for Routers
 
Inline intrusion prevention for Linux routers. Drops malicious forwarded traffic through NFQUEUE and detects attacks inside the LAN, seen through mirrored traffic.
 
> Work in progress. Not ready for real networks.
 
## Features
 
- Inline ACCEPT/DROP verdicts on forwarded traffic (NFQUEUE)
- Capture of mirrored LAN traffic (libpcap, promiscuous mode)
- Both paths parse into one packet struct and go through the same detection engine
- Per-source sliding-window rate counters, with idle sources cleaned up in the background
- Pluggable detectors: each attack is one class implementing `Detector`, registered in `Engine`
Detectors:
 
| Attack | Path | Status |
|---|---|---|
| ICMP flood | inline (DROP) and mirrored (alert) | done |
| ARP spoofing | mirrored, corrective ARP | sprint 2 |
| SYN flood, UDP flood | inline | sprint 3 |
| DHCP starvation | mirrored | sprint 3 |
| Port scan, DNS spoofing, TCP RST injection | inline and mirrored | sprint 4 |
| SQL injection, command injection, ICMP tunneling | inline | sprint 5 |
  
## Requirements
 
- Linux with iptables and `tc`
- root, or `CAP_NET_ADMIN` + `CAP_NET_RAW`
- C++17 compiler, CMake 3.16+
- `libnetfilter-queue-dev`, `libpcap-dev`
- Docker + Compose plugin, for the lab
## Quick start
 
The repo ships a lab: a router running spider, two clients (`client1`, `client2`) on `lannet` (10.0.1.0/24), and a host called `outside` on `wannet` (10.0.2.0/24).
 
```bash
git clone https://gitlab.com/guypro0906/netanya-904-spider.git
cd netanya-904-spider
docker compose up --build -d
```
 
Set up LAN mirroring before starting spider. LAN hosts talk to each other directly through the bridge, so without this spider only sees router-crossing traffic:
 
```bash
sudo ./mirror.sh
```
 
Start spider on the router's LAN interface, the one holding `10.0.1.254`. Docker doesn't guarantee whether that is `eth0` or `eth1`, so look it up first:
 
```bash
docker compose exec router ip -o -4 addr show
docker compose exec router ./spider <lan-interface>
```
 
From another terminal:
 
```bash
docker compose exec client1 ping 10.0.2.10
```
 
## Mirroring
 
client1 and client2 talk to each other directly through the Docker bridge, so those frames never reach the router. Without mirroring, spider only sees router-crossing traffic.
 
**Docker lab:** `mirror.sh` does it for you. Run it on the host, from the repo directory, after the lab is up. It finds each container's host-side veth and adds a `tc` rule that copies the client's frames to the router's veth. Frames already addressed to the router, and broadcasts, are skipped since the router gets those anyway.
 
Veth names change whenever containers are recreated, so rerun it after every `docker compose up` that recreates them. To mirror more clients, add them to `CLIENTS` at the top of the script.
 
**Physical switches:** configure port mirroring (SPAN) with the router's LAN port as the destination. Steps depend on the vendor.
 
## Running on a host
 
```bash
cmake -S . -B build && cmake --build build
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
sudo ./build/spider <lan-interface>
```
 
`<lan-interface>` is where spider captures mirrored traffic. Its libpcap filter ignores frames to or from that interface's own MAC address, so traffic that crosses the router is counted once, by NFQUEUE. The queue number (0) is hardcoded until the config file lands in sprint 3.
 
## How it works
 
Router-crossing traffic: `FORWARD -> NFQUEUE -> spider -> ACCEPT/DROP`
 
LAN-internal traffic: `tc mirred -> router LAN iface -> libpcap -> spider -> alert/response`
 
Each capture source runs on its own thread and calls `Engine::process()` directly from its callback. The packet is parsed, passed to every detector that wants it, and discarded. Only counters and tables are kept, so there's no packet queue between threads.
 
## Status
 
**Sprint 1: capture** (done)
- [x] Docker lab
- [x] NFQUEUE capture on FORWARD
- [x] libpcap capture of mirrored LAN traffic
- [x] Unified packet struct and parser
- [x] `Detector` interface
**Sprint 2: first defense on each side** (in progress)
- [x] Sliding-window packet counter and state cleanup
- [x] Engine with detector registration
- [x] ICMP flood detection + attack script
- [ ] Logger
- [ ] ARP parsing and IP to MAC table
- [ ] Raw socket responses
- [ ] ARP spoofing detection with corrective ARP
**Sprint 3: floods and DHCP**
- [ ] TCP, UDP and DHCP parsing
- [ ] Config file for thresholds, windows and interfaces
- [ ] Logger on its own thread
- [ ] SYN flood, UDP flood, DHCP starvation
**Sprint 4: scans, DNS, TCP state**
- [ ] Port scan, DNS spoofing
- [ ] TCP connection tracking, RST injection
**Sprint 5: payload inspection**
- [ ] SQL injection, command injection, ICMP tunneling
- [ ] Per-packet processing time stats
- [ ] One-command lab setup
## Authors
 
Guy Molnar, Guy Ravillan
