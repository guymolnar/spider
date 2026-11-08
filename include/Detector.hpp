#pragma once
#include "Packet.hpp"

class Detector
{
public:
    virtual ~Detector() = default;
    virtual bool inspect(const Packet& packet) = 0;
    virtual bool wants(const Packet& packet) const = 0;
};