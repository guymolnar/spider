#include "PcapCapture.hpp"
#include "Engine.hpp"

#include <iostream>
#include <stdexcept>

static void onPacket(u_char* user, const pcap_pkthdr* header, const u_char* bytes)
{
    auto* engine = reinterpret_cast<Engine*>(user);

    if (engine->process(bytes, header->caplen, Source::Mirror) == Verdict::DROP)
    {
        std::cout << "[pcap] ALERT attack detected\n";
    }
}

PcapCapture::PcapCapture(const std::string& iface, Engine& engine)
    : _engine(engine)
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
    if (pcap_loop(_handle, -1, onPacket, reinterpret_cast<u_char*>(&_engine)) == -1)
    {
        std::cerr << "pcap_loop: " << pcap_geterr(_handle) << '\n';
    }
}