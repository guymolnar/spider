#pragma once
#include "Detector.hpp"
#include "PacketCounter.hpp"
#include "StateManager.hpp"
#include <chrono>
#include <iostream>
class IcmpFloodDetector : public Detector
{
public:
    IcmpFloodDetector(uint32_t threshold, std::chrono::steady_clock::duration window);
    Verdict inspect(const Packet& packet) override;
    bool wants(const Packet& packet) const override;
private:
    PacketCounter& _counter;
    uint32_t _threshold;
};