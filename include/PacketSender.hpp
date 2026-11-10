#pragma once
#include <cstdint>
#include <string>
#include <net/ethernet.h>
#include <pcap/pcap.h>

class PacketSender
{
public:
    PacketSender(const std::string& iface);
    ~PacketSender();
   // broadcasts "who has targetIp?", the answers come back through the main capture
    bool sendArpRequest(uint32_t targetIp);

    uint32_t routerIp() const { return _routerIp; }
    const uint8_t* routerMac() const { return _routerMac; }

private:
    void readRouterAddresses(const std::string& iface);
    bool sendArp(uint16_t op, const uint8_t dstMac[ETH_ALEN], const uint8_t senderMac[ETH_ALEN], uint32_t senderIp,
                 const uint8_t targetMac[ETH_ALEN], uint32_t targetIp);

    pcap_t* _pcapHandle = nullptr;
    uint8_t _routerMac[ETH_ALEN];
    uint32_t _routerIp; // network order
};