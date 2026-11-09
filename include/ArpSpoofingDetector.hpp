#pragma once
#include "Detector.hpp"
#include "Logger.hpp"
#include <unordered_map>    

class ArpSpoofingDetector : public Detector
{
public:
    ArpSpoofingDetector(std::unordered_map<uint32_t, uint32_t> ipToMacTable, Logger& logger);
    bool inspect(const Packet& packet) override;
    bool wants(const Packet& packet) const override;
private:
    Logger& _logger;
    std::unordered_map<uint32_t, uint32_t> _ipToMacTable;

};
