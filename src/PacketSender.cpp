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

PacketSender::PacketSender(const std::string& iface)
{
    readRouterAddresses(iface);

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
