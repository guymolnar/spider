#pragma once

#include <pcap/pcap.h>
#include <string>

class IcmpFloodDetector;

class PcapCapture
{
public:
    PcapCapture(const std::string& iface, IcmpFloodDetector* detector = nullptr);
    ~PcapCapture();

    PcapCapture(const PcapCapture&) = delete;
    PcapCapture& operator=(const PcapCapture&) = delete;

    void run();

private:
    pcap_t* _handle = nullptr;
    IcmpFloodDetector* _detector = nullptr;     // not owned, main keeps it alive
};