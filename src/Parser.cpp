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
        parseEthernet(p, data, len);
    }
    else
    {
        return true;
    }
}