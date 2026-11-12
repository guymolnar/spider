#include "PacketSender.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h> 
#include <fstream>
#include <netinet/ether.h>

PacketSender::PacketSender(const std::string& iface, uint32_t routerIp) : _routerIp(routerIp){
    readRouterMac(iface);

    char errbuf[PCAP_ERRBUF_SIZE];
    _pcapHandle = pcap_create(iface.c_str(), errbuf);
    if (!_pcapHandle)
    {
        throw std::runtime_error("error creating sender pcap handle: " + std::string(errbuf));
    }

    // this handle only sends, replies come back through the main capture
    if (pcap_activate(_pcapHandle) < 0)
    {
        std::string why = pcap_geterr(_pcapHandle);
        pcap_close(_pcapHandle);
        throw std::runtime_error("error activating sender pcap handle: " + why);
    }
}

PacketSender::~PacketSender()
{
    if (_pcapHandle)
    {
        pcap_close(_pcapHandle);
    }
}

void PacketSender::readRouterMac(const std::string& iface)
{
    // the kernel exposes the mac as text like "02:42:0a:00:01:01"
    std::ifstream file("/sys/class/net/" + iface + "/address");
    std::string text;
    if (!std::getline(file, text))
    {
        throw std::runtime_error("failed to read mac of " + iface);
    }
    ether_addr mac;
    if (!ether_aton_r(text.c_str(), &mac))
    {
        throw std::runtime_error("bad mac format for " + iface + ": " + text);
    }
    std::memcpy(_routerMac, mac.ether_addr_octet, ETH_ALEN);
}

bool PacketSender::sendArpRequest(uint32_t targetIp)
{
    uint8_t broadcast[ETH_ALEN];
    uint8_t unknown[ETH_ALEN] = {0}; // the mac we are asking for
    std::memset(broadcast, 0xFF, ETH_ALEN);

    return sendArp(ARPOP_REQUEST, broadcast, _routerMac, _routerIp, unknown, targetIp);
}

bool PacketSender::sendArp(uint16_t op, const uint8_t dstMac[ETH_ALEN], const uint8_t senderMac[ETH_ALEN], uint32_t senderIp,
                           const uint8_t targetMac[ETH_ALEN], uint32_t targetIp)
{
    uint8_t frame[sizeof(ether_header) + sizeof(ether_arp)] = {0};
    ether_header* eth = reinterpret_cast<ether_header*>(frame);
    ether_arp* arp = reinterpret_cast<ether_arp*>(frame + sizeof(ether_header));

    std::memcpy(eth->ether_dhost, dstMac, ETH_ALEN);
    // the frame always leaves from the router, even when the arp body speaks for another host
    // using the other host's mac here would make the switch send that host's traffic to us
    std::memcpy(eth->ether_shost, _routerMac, ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_ARP);

    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = sizeof(senderIp);
    arp->ea_hdr.ar_op = htons(op);
    std::memcpy(arp->arp_sha, senderMac, ETH_ALEN);
    std::memcpy(arp->arp_spa, &senderIp, sizeof(senderIp));
    std::memcpy(arp->arp_tha, targetMac, ETH_ALEN);
    std::memcpy(arp->arp_tpa, &targetIp, sizeof(targetIp));

    return pcap_inject(_pcapHandle, frame, sizeof(frame)) == static_cast<int>(sizeof(frame));
}

bool PacketSender::sendArpCorrection(uint32_t claimedIp, const uint8_t* trustedMac)
{
    // broadcast, a spoofed reply may have reached more hosts than the one it was sent to
    // hosts only update an entry they already have, so clean hosts are not affected
    uint8_t broadcast[ETH_ALEN];
    std::memset(broadcast, 0xFF, ETH_ALEN);

    return sendArp(ARPOP_REPLY, broadcast, trustedMac, claimedIp, trustedMac, claimedIp);
}
