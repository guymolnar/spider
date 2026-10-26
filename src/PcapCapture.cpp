#include "PcapCapture.hpp"

#include <iostream>
#include <stdexcept>

static void onPacket(u_char*, const pcap_pkthdr* header, const u_char*)
{
    std::cout << "[pcap] captured " << header->caplen << " of " << header->len << " bytes\n";
}

PcapCapture::PcapCapture(const std::string& iface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    _handle = pcap_open_live(iface.c_str(), 65535, 1, 1000, errbuf); //third parameter is promiscious mode
    if (!_handle)
    {
        throw std::runtime_error(errbuf);
    }
}

PcapCapture::~PcapCapture()
{
    if (_handle)
    {
        pcap_close(_handle);
    }
}

void PcapCapture::run()
{
    if (pcap_loop(_handle, -1, onPacket, nullptr) == -1)
    {
        std::cerr << "pcap_loop: " << pcap_geterr(_handle) << '\n';
    }
}