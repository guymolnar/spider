#pragma once
#include <cstdint>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct Packet{
    const ether_header* _eth = nullptr;
    const ether_arp* _arp = nullptr;
    const ip* _ip4 = nullptr;
    const tcphdr* _tcp = nullptr;
    const udphdr* _udp = nullptr;
    const icmphdr* _icmp = nullptr;

    const uint8_t* _payload = nullptr;
    size_t _payloadLen = 0;
};