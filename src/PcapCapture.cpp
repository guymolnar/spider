#include "PcapCapture.hpp"
#include "IcmpFloodDetector.hpp"
#include "Parser.hpp"

#include <iostream>
#include <stdexcept>

static void onPacket(u_char* user, const pcap_pkthdr* header, const u_char* bytes)
{
    auto* detector = reinterpret_cast<IcmpFloodDetector*>(user);

    std::cout << "[pcap] captured " << header->caplen << " of " << header->len << " bytes\n";

    Packet pkt;
    if (!detector || !Parser::parse(bytes, header->caplen, Source::Mirror, pkt))
    {
        return;
    }

    // mirror mode only sees a copy, so a DROP verdict can only be reported, not enforced
    if (detector->wants(pkt) && detector->inspect(pkt) == Verdict::DROP)
    {
        std::cout << "[pcap] ALERT icmp flood detected\n";
    }
}

PcapCapture::PcapCapture(const std::string& iface, IcmpFloodDetector* detector)
    : _detector(detector)
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
    if (pcap_loop(_handle, -1, onPacket, reinterpret_cast<u_char*>(_detector)) == -1)
    {
        std::cerr << "pcap_loop: " << pcap_geterr(_handle) << '\n';
    }
}