#pragma once
#include "Detector.hpp"
#include "Logger.hpp"
#include "StateManager.hpp"
#include <cstdint>
#include <unordered_map>

class ArpSpoofingDetector : public Detector
{
public:
    ArpSpoofingDetector(std::unordered_map<uint32_t, ArpEntry>& table, Logger& logger);
    bool inspect(const Packet& packet) override;
    bool wants(const Packet& packet) const override;
private:
    std::unordered_map<uint32_t, ArpEntry>& _table;     // owned by the state manager
    Logger& _logger;
};
