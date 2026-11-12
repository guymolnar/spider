#pragma once
class Logger;
class PacketSender;

#include "Packet.hpp"

#include <string>
#include <unordered_set>

enum class Verdict
{
    ALLOW,
    DROP
};

class Responder
{
public:
    Verdict respond(bool attackDetected, Source source) const;
    Responder(PacketSender& sender, const std::string& iface, Logger& logger);
    ~Responder();

    Responder(const Responder&) = delete;
    Responder& operator=(const Responder&) = delete;

    void correctArp(uint32_t claimedIp, const uint8_t* trustedMac);
private:
    // the corrective broadcast never reaches our own arp handling, so the router's cache is written directly
    void pinArp(uint32_t ip, const uint8_t* mac);
    bool runIp(const std::string& args) const;

    PacketSender& _sender;
    std::string _iface;
    Logger& _logger;
    std::unordered_set<uint32_t> _pinned;   // ips we made permanent, removed again on shutdown
};
