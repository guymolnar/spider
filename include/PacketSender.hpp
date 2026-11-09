#pragma once
#include <cstdint>
#include <pcap/pcap.h>

class PacketSender
{
public:
    PacketSender(const uint8_t* routerMac, const uint8_t* routerIp);
    uint8_t* sendArpRequest(uint32_t targetIp);
private:
    pcap_t* _pcapHandle;
    uint8_t _routerMac[6];
    uint8_t _routerIp[4];
};

