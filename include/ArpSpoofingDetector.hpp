#pragma once
#include "Detector.hpp"
#include "Logger.hpp"
#include "StateManager.hpp"
#include <cstdint>
#include <unordered_map>
#include "PacketSender.hpp"
#include "Responder.hpp"

class ArpSpoofingDetector : public Detector
{
public:
    ArpSpoofingDetector(std::unordered_map<uint32_t, ArpEntry>& table, PacketSender& sender, Responder& responder, Logger& logger);
    bool inspect(const Packet& packet) override;
    bool wants(const Packet& packet) const override;
private:
    void decideExpired(std::chrono::steady_clock::time_point now);
    std::unordered_map<uint32_t, ArpEntry>& _table;     // owned by the state manager
    PacketSender& _sender;
    Logger& _logger;
    Responder& _responder;
};
