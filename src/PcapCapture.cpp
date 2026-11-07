#include "PcapCapture.hpp"
#include "Engine.hpp"
#include "Logger.hpp"

#include <stdexcept>
#include <fstream>


static void onPacket(u_char* user, const pcap_pkthdr* header, const u_char* bytes)
{
    auto* engine = reinterpret_cast<Engine*>(user);

    // mirrored traffic can't be dropped, the detectors log their own alerts
    engine->process(bytes, header->caplen, Source::Mirror);
}

PcapCapture::PcapCapture(const std::string& iface, Engine& engine, Logger& logger)
    : _engine(engine), _logger(logger)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string expr = "not (ip and ether host " + readMac(iface) + ")";
    _handle = pcap_create(iface.c_str(), errbuf); // check if the interface exists
    if (!_handle)
    {
        throw std::runtime_error("error creating pcap handle: " + std::string(errbuf));
    }
    
    pcap_set_snaplen(_handle, 65535);
    pcap_set_promisc(_handle, 1);
    pcap_set_immediate_mode(_handle, 1);
    if (pcap_activate(_handle) < 0)
    {
        std::string why = pcap_geterr(_handle);
        pcap_close(_handle);
        throw std::runtime_error("error activating pcap handle: " + why);
    }

    bpf_program bpf;
    if (pcap_compile(_handle, &bpf, expr.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        std::string why = pcap_geterr(_handle);
        pcap_close(_handle);
        throw std::runtime_error("error compiling pcap filter: " + why);
    }

    if (pcap_setfilter(_handle, &bpf) < 0)
    {
        std::string why = pcap_geterr(_handle);
        pcap_freecode(&bpf);
        pcap_close(_handle);
        throw std::runtime_error("error setting pcap filter: " + why);
    }
    pcap_freecode(&bpf);
    _logger.log("pcap: capturing on " + iface + ", filter: " + expr);
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
        _logger.log(std::string("pcap: pcap_loop failed: ") + pcap_geterr(_handle));
    }
}

std::string PcapCapture::readMac(const std::string& iface)
{
    std::string path = "/sys/class/net/" + iface + "/address";
    std::ifstream file(path);
    if (!file.is_open())
    {
        throw std::runtime_error("failed to open " + path);
    }
    std::string mac;
    std::getline(file, mac);
    file.close();
    return mac;
}