#include "IcmpFloodDetector.hpp"

IcmpFloodDetector::IcmpFloodDetector(uint32_t threshold, std::chrono::steady_clock::duration window) : _counter(StateManager().makeCounter(window)), _threshold(threshold)
{
}

bool IcmpFloodDetector::wants(const Packet& packet) const
{
    return packet.icmp != nullptr;
}

Verdict IcmpFloodDetector::inspect(const Packet& packet)
{
    if (packet.icmp == nullptr)
    {
        return Verdict::ALLOW;
    }

    uint32_t srcIp = ntohl(packet.ip4->ip_src.s_addr);
    auto now = std::chrono::steady_clock::now();
    _counter.record(srcIp, now);
    uint32_t rate = _counter.rate(srcIp, now);

    if (rate > _threshold)
    {
        std::cout << "[ICMP Flood Detector] Dropping packet from " << (srcIp >> 24) << "." << ((srcIp >> 16) & 0xFF) << "." << ((srcIp >> 8) & 0xFF) << "." << (srcIp & 0xFF) << " with rate " << rate << " pps\n";
        return Verdict::DROP;
    }
    else
    {
        return Verdict::ALLOW;
    }
}