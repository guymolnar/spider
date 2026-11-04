#pragma once

#include <cstdint>

#include "Detector.hpp"
#include "PacketCounter.hpp"

class IcmpFloodDetector : public Detector
{
public:
    IcmpFloodDetector(PacketCounter& counter, uint32_t threshold);

    Verdict inspect(const Packet& packet) override;
    bool wants(const Packet& packet) const override;

private:
    PacketCounter& _counter; 
    uint32_t _threshold;     
};
