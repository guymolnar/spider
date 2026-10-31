#include "Parser.hpp"

bool Parser::parseEthernet(Packet& p, const uint8_t* data, size_t len)
{
    if(len < sizeof(ether_header))
    {
        return false;
    }
    p._eth = reinterpret_cast<const ether_header*>(data);    
    uint16_t type = ntohs(p._eth->ether_type);
    data += sizeof(ether_header);
    len  -= sizeof(ether_header);

    switch (type)
    {
    case ETHERTYPE_ARP:
        return parseArp(p, data, len);
    case ETHERTYPE_IP:
        return parseIpv4(p, data, len);
    default:
        break;
    }
}

bool Parser::parseArp(Packet& p, const uint8_t* data, size_t len)
{
    if(len < sizeof(ether_arp))
    {
        return false;
    }
    const ether_arp* arp = reinterpret_cast<const ether_arp*>(data);  
    if (ntohs(arp->arp_hrd) != ARPHRD_ETHER || ntohs(arp->arp_pro) != ETHERTYPE_IP || arp->arp_hln != 6 || arp->arp_pln != 4)
    {
        return false;
    }

    p._arp = arp;
    return true;
}

bool Parser::parseIpv4(Packet& p, const uint8_t* data, size_t len)
{
    if(len < sizeof(ip))
    {
        return false;
    }

    const ip* iph = reinterpret_cast<const ip*>(data);
    if (iph->ip_v != 4)
    {
        return false;
    }

    size_t hdrLen = iph->ip_hl * 4;
    size_t totalLen = ntohs(iph->ip_len);

    // Header length: at least 20, and not past the buffer
    if (hdrLen < sizeof(ip) || hdrLen > len)
    {
        return false;
    }

    // Total length: covers the header, and not past the buffer
    if (totalLen < hdrLen || totalLen > len)
    {
        return false;
    }

    len = totalLen;
    p._ip4 = iph;
    if (ntohs(iph->ip_off) & IP_OFFMASK)
    {
        return true;
    }
    data += hdrLen;
    len -= hdrLen;
    switch(iph->ip_p)
    {
        case IPPROTO_TCP:  
            return parseTcp(p, data, len);
        case IPPROTO_UDP:  
            return parseUdp(p, data, len);
        case IPPROTO_ICMP: 
            return parseIcmp(p, data, len);
        default: 
            return true;
    }
}

bool Parser::parseTcp(Packet& p, const uint8_t* data, size_t len)
{
    if(len < sizeof(tcphdr))
    {
        return false;
    }
    const tcphdr* tcph = reinterpret_cast<const tcphdr*>(data);
    size_t hdrLen = tcph->doff * 4;
    if(hdrLen < sizeof(tcphdr) || hdrLen > len)
    {
        return false;
    }
    p._tcp = tcph;
    data += hdrLen;
    len -= hdrLen;
    p._payload = data;
    p._payloadLen = len;
    return true;
}