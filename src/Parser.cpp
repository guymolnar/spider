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
    if(type == ETHERTYPE_ARP)
    {
        parseArp(p, data, len);
    }
    else if(type == ETHERTYPE_IP)
    {
        parseIpv4(p, data, len);
    }
    else
    {
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
        return true;
    }

    p._arp = arp;
    return true;
}