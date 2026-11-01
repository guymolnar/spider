#pragma once
#include "Packet.hpp"

enum class Verdict
{
    ALLOW,
    DROP
};

class Detector
{
public:
    virtual ~Detector() = default;
    virtual Verdict inspect(const Packet& packet) = 0;
    virtual bool wants(const Packet& packet) const = 0;
};