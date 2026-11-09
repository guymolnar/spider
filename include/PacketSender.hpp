#pragma once
#include <cstdint>
#include <pcap/pcap.h>

class PacketSender
{
public:
    PacketSender(const uint8_t* routerMac, const uint8_t* routerIp, const std::string& iface);
    uint8_t* sendArpRequest(uint32_t targetIp);
private:
    pcap_t* _pcapHandle;
    const uint8_t* _routerMac;
    const uint8_t* _routerIp;
};

