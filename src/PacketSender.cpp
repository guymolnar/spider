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

PacketSender::PacketSender(const std::string& iface)
{
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