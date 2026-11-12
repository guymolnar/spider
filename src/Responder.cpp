#include "Responder.hpp"
#include "Logger.hpp"
#include "PacketSender.hpp"

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <cstring>
#include <cstdlib>

static std::string ipToString(uint32_t ip)
{
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));
    return buf;
}

Verdict Responder::respond(bool attackDetected, Source source) const
{
    if (attackDetected && source == Source::Inline)
    {
        return Verdict::DROP;
    }

    return Verdict::ALLOW;
}

Responder::Responder(PacketSender& sender, const std::string& iface, Logger& logger) : _sender(sender), _iface(iface), _logger(logger)
{
}

Responder::~Responder()
{
    //permanent entries outlive us, if a host later changes mac the router would keep using the old one
    for (uint32_t ip : _pinned)
    {
        const bool removed = runIp("neigh del " + ipToString(ip) + " dev " + _iface);
        _logger.log("response: unpinned " + ipToString(ip) + (removed ? "" : " failed"));
    }
}

void Responder::correctArp(uint32_t claimedIp, const uint8_t* trustedMac)
{
    const bool sent = _sender.sendArpCorrection(claimedIp, trustedMac);
    _logger.log("response: corrective ARP for " + ipToString(claimedIp) + (sent ? " sent" : " failed"));

    // the router's own ip is not in its own cache, there is nothing to pin
    if (claimedIp != _sender.routerIp())
    {
        pinArp(claimedIp, trustedMac);
    }
}

void Responder::pinArp(uint32_t ip, const uint8_t* mac)
{
    // once pinned the kernel ignores further lies, so running the command again changes nothing
    if (_pinned.count(ip))
    {
        return;
    }

    ether_addr addr;
    std::memcpy(addr.ether_addr_octet, mac, ETH_ALEN);
    char macStr[18];
    ether_ntoa_r(&addr, macStr);

    const bool pinned = runIp("neigh replace " + ipToString(ip) + " lladdr " + macStr + " dev " + _iface + " nud permanent");
    if (pinned)
    {
        _pinned.insert(ip);
    }
    _logger.log("response: pinned " + ipToString(ip) + " to " + macStr + (pinned ? "" : " failed"));
}

bool Responder::runIp(const std::string& args) const
{
    return std::system(("ip " + args).c_str()) == 0;
}
