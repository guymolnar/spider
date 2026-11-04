#pragma once

#include <pcap/pcap.h>
#include <string>

class Engine;

class PcapCapture
{
public:
    PcapCapture(const std::string& iface, Engine* engine);
    ~PcapCapture();

    PcapCapture(const PcapCapture&) = delete;
    PcapCapture& operator=(const PcapCapture&) = delete;

    void run();

private:
    pcap_t* _handle = nullptr;
    Engine* _engine = nullptr;
};