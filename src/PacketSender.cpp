#include "PacketSender.hpp"
#include <stdexcept>

PacketSender::PacketSender(const uint8_t* routerMac, const uint8_t* routerIp, const std::string& iface)
{
    _pcapHandle = pcap_open_live(iface.c_str(), 65535, 1, 1000, nullptr);
    if (!_pcapHandle)
    {
        throw std::runtime_error("PacketSender: cannot open pcap handle");
    }
    _routerMac = routerMac;
    _routerIp = routerIp;
}

