#pragma once

#include <pcap/pcap.h>
#include <string>

class PcapCapture
{
public:
    explicit PcapCapture(const std::string& iface);
    ~PcapCapture();

    PcapCapture(const PcapCapture&) = delete;
    PcapCapture& operator=(const PcapCapture&) = delete;

    void run();

private:
    pcap_t* _handle = nullptr;
};