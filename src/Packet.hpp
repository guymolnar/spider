#pragma once
#include <cstdint>
#include <cstddef>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

enum class Source 
{ 
    Inline, 
    Mirror 
};

struct Packet{
    Source source;
    const ether_header* eth = nullptr;
    const ether_arp* arp = nullptr;
    const ip* ip4 = nullptr;
    const tcphdr* tcp = nullptr;
    const udphdr* udp = nullptr;
    const icmphdr* icmp = nullptr;

    const uint8_t* payload = nullptr;
    size_t payloadLen = 0;
};