#pragma once
class Logger;
class PacketSender;

#include "Packet.hpp"

enum class Verdict
{
    ALLOW,
    DROP
};

class Responder
{
public:
    Verdict respond(bool attackDetected, Source source) const;
    Responder(PacketSender& sender, Logger& logger);
    void correctArp(uint32_t claimedIp, const uint8_t* trustedMac, const uint8_t* recipientMac) const;
private:
    PacketSender& _sender;
    Logger& _logger;
};