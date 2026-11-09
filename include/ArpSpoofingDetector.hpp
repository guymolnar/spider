#pragma once
#include "Detector.hpp"
#include "Logger.hpp"
#include <unordered_map>

class ArpSpoofingDetector : public Detector
{
public:
    ArpSpoofingDetector(Logger& logger);
    bool inspect(const Packet& packet) override;
    bool wants(const Packet& packet) const override;
private:
    std::unordered_map<uint32_t, uint32_t> _ipToMac; // mapping of IP addresses to MAC addresses
    Logger& _logger;

};
