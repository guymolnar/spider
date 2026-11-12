#include "Responder.hpp"
#include "Logger.hpp"
#include "PacketSender.hpp"

#include <arpa/inet.h>

Verdict Responder::respond(bool attackDetected, Source source) const
{
    if (attackDetected && source == Source::Inline)
    {
        return Verdict::DROP;
    }

    return Verdict::ALLOW;
}

Responder::Responder(PacketSender& sender, Logger& logger) : _sender(sender), _logger(logger)
{
}

void Responder::correctArp(uint32_t claimedIp, const uint8_t* trustedMac) const
{
    const bool sent = _sender.sendArpCorrection(claimedIp, trustedMac);

    char ip[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &claimedIp, ip, sizeof(ip));

    _logger.log(std::string("response: corrective ARP for ") + ip + (sent ? " sent" : " failed"));
}