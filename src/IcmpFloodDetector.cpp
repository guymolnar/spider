#include "IcmpFloodDetector.hpp"

#include "Logger.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <string>

IcmpFloodDetector::IcmpFloodDetector(PacketCounter& counter, uint32_t threshold, Logger& logger)
    : _counter(counter), _threshold(threshold), _logger(logger)
{
}

bool IcmpFloodDetector::wants(const Packet& packet) const
{
    // echo requests only: counting replies would flag a host that is being pinged legitimately
    return packet.ip4 && packet.icmp && packet.icmp->type == ICMP_ECHO;
}

bool IcmpFloodDetector::inspect(const Packet& packet)
{
    auto now = std::chrono::steady_clock::now();
    uint32_t src = packet.ip4->ip_src.s_addr;    

    _counter.record(src, now);

    uint32_t rate = _counter.rate(src, now);
    if (rate > _threshold)
    {
        // rate grows by one per packet, so it equals threshold + 1 once per flood: log only then
        if (rate == _threshold + 1)
        {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &packet.ip4->ip_src, ip, sizeof(ip));
            _logger.log(std::string("ALERT icmp flood src=") + ip +
                        " rate=" + std::to_string(rate) +
                        " threshold=" + std::to_string(_threshold) +
                        " path=" + (packet.source == Source::Inline ? "inline" : "mirror"));
        }
        return Verdict::DROP;
    }
    return Verdict::ALLOW;
}
