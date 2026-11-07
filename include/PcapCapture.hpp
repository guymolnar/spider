#pragma once

#include <pcap/pcap.h>
#include <string>

class Engine;
class Logger;

class PcapCapture
{
public:
    PcapCapture(const std::string& iface, Engine& engine, Logger& logger);
    ~PcapCapture();

    PcapCapture(const PcapCapture&) = delete;
    PcapCapture& operator=(const PcapCapture&) = delete;

    void run();

private:
    pcap_t* _handle = nullptr;
    Engine& _engine;
    Logger& _logger;
    static std::string readMac(const std::string& iface);
};