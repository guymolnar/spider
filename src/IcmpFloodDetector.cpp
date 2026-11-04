#include "IcmpFloodDetector.hpp"

#include <chrono>

IcmpFloodDetector::IcmpFloodDetector(PacketCounter& counter, uint32_t threshold)
    : _counter(counter), _threshold(threshold)
{
}

bool IcmpFloodDetector::wants(const Packet& packet) const
{
    // echo requests only: counting replies would flag a host that is being pinged legitimately
    return packet.ip4 && packet.icmp && packet.icmp->type == ICMP_ECHO;
}

Verdict IcmpFloodDetector::inspect(const Packet& packet)
{
    auto now = std::chrono::steady_clock::now();
    uint32_t src = packet.ip4->ip_src.s_addr;    

    _counter.record(src, now);

    if (_counter.rate(src, now) > _threshold)
    {
        return Verdict::DROP;
    }
    return Verdict::ALLOW;
}
