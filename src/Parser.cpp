#include "Parser.hpp"



bool Parser::parse(const uint8_t* data, size_t len, Source source, Packet& out)
{
    out = Packet();
    out.source = source;

    if(source == Source::Mirror)
    {
        return parseEthernet(out, data, len);
    }
    else
    {
        return parseIpv4(out, data, len);
    }
}


bool Parser::parseEthernet(Packet& p, const uint8_t* data, size_t len)
{
    if(len < sizeof(ether_header))
    {
        return false;
    }
    p.eth = reinterpret_cast<const ether_header*>(data);    
    uint16_t type = ntohs(p.eth->ether_type);
    data += sizeof(ether_header);
    len  -= sizeof(ether_header);

    switch (type)
    {
    case ETHERTYPE_ARP:
        return parseArp(p, data, len);
    case ETHERTYPE_IP:
        return parseIpv4(p, data, len);
    default:
        return true;
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

    p.arp = arp;
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
    p.ip4 = iph;
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
    p.tcp = tcph;
    data += hdrLen;
    len -= hdrLen;
    p.payload = data;
    p.payloadLen = len;
    return true;
}

bool Parser::parseUdp(Packet& p, const uint8_t* data, size_t len)
{
    if(len < sizeof(udphdr))
    {
        return false;
    }
    const udphdr* udph = reinterpret_cast<const udphdr*>(data);
    size_t udpLen = ntohs(udph->len);
    if (udpLen < sizeof(udphdr) || udpLen > len) //the headers length is consatnt
    {
        return false;
    }
    p.udp = udph;
    len = udpLen;
    data += sizeof(udphdr);
    len -= sizeof(udphdr);
    p.payload = data;
    p.payloadLen = len;
    return true;
}

bool Parser::parseIcmp(Packet& p, const uint8_t* data, size_t len)
{
    if(len < sizeof(icmphdr))
    {
        return false;
    }
    const icmphdr* icmp_hdr = reinterpret_cast<const icmphdr*>(data);
    p.icmp = icmp_hdr;
    data += sizeof(icmphdr);
    len -= sizeof(icmphdr);
    p.payload = data;
    p.payloadLen = len;
    return true;
}