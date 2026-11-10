#include "ArpSpoofingDetector.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <netinet/ether.h>
#include <string>

static std::string macToString(const uint8_t* mac)
{
    ether_addr addr;
    std::memcpy(addr.ether_addr_octet, mac, ETH_ALEN);
    char buf[18];
    return ether_ntoa_r(&addr, buf);
}

static std::string ipToString(uint32_t ip)
{
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));
    return buf;
}

ArpSpoofingDetector::ArpSpoofingDetector(std::unordered_map<uint32_t, ArpEntry>& table, PacketSender& sender, Logger& logger) : _table(table), _sender(sender), _logger(logger)
{
    // the router's pair comes from its own interface, so it is trusted without a probe
    ArpEntry& router = _table[_sender.routerIp()];
    router.status = ArpStatus::Trusted;
    std::copy(_sender.routerMac(), _sender.routerMac() + ETH_ALEN, router.mac.begin());
}

bool ArpSpoofingDetector::wants(const Packet& packet) const
{
    //Only check for a VALID arp packet
    return packet.eth && packet.arp && ntohs(packet.eth->ether_type) == ETHERTYPE_ARP;
}

bool ArpSpoofingDetector::inspect(const Packet& packet)
{
    auto now = std::chrono::steady_clock::now();
    decideExpired(now);   // only inspect reads the table, so settling here is always in time

    uint32_t senderIp;
    std::memcpy(&senderIp, packet.arp->arp_spa, sizeof(senderIp));
    if (senderIp == 0)
    {
        return false;   // arp probe (0.0.0.0), a host checking if an ip is free, claims nothing
    }
    const uint8_t* senderMac = packet.arp->arp_sha;

    auto it = _table.find(senderIp);
    if (it == _table.end())
    {
        // first claim for this ip, we cant trust it so we ask the network who really has it
        // the claim itself is not counted, only what arrives during the probe window
        ArpEntry& entry = _table[senderIp];
        entry.status = ArpStatus::Pending;
        entry.deadline = now + std::chrono::seconds(1);
        _sender.sendArpRequest(senderIp);
        return false;
    }

    ArpEntry& entry = it->second;

    if (entry.status == ArpStatus::Pending)
    {

        std::array<uint8_t, ETH_ALEN> mac;
        std::copy(senderMac, senderMac + ETH_ALEN, mac.begin());
        // count macs not packets, the same host may answer twice
        if (std::find(entry.answers.begin(), entry.answers.end(), mac) == entry.answers.end())
        {
            entry.answers.push_back(mac);
        }

        if (entry.answers.size() > 1)
        {
            // two different macs answered for the same ip, one of them is lying and we cant tell which
            std::string macs;
            for (const auto& answer : entry.answers)
            {
                macs += " " + macToString(answer.data());
            }
            _logger.log("ALERT arp conflict ip=" + ipToString(senderIp) + " answered by" + macs);
            _table.erase(it);
            return true;
        }
        return false;
    }

    if (std::equal(entry.mac.begin(), entry.mac.end(), senderMac))
    {
        return false;
    }

    if (now - entry.lastAlert >= std::chrono::seconds(5))
    {
        entry.lastAlert = now;
        _logger.log("ALERT arp spoofing ip=" + ipToString(senderIp) +
                    " real=" + macToString(entry.mac.data()) +
                    " claimed=" + macToString(senderMac) +
                    " path=" + (packet.source == Source::Inline ? "inline" : "mirror"));
    }
    return true;
}

void ArpSpoofingDetector::decideExpired(std::chrono::steady_clock::time_point now)
{
    // without this, an ip whose probe got no more packets would stay pending forever
    for (auto it = _table.begin(); it != _table.end();)
    {
        ArpEntry& entry = it->second;
        if (entry.status != ArpStatus::Pending || now < entry.deadline)
        {
            ++it;
            continue;
        }

        if (entry.answers.size() == 1)
        {
            entry.status = ArpStatus::Trusted;
            entry.mac = entry.answers[0];
            entry.answers.clear();
            ++it;
        }
        else
        {
            it = _table.erase(it);   // nobody answered, forget it and probe again on the next claim
        }
    }
}
