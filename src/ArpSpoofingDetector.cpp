#include "ArpSpoofingDetector.hpp"

ArpSpoofingDetector::ArpSpoofingDetector(std::unordered_map<uint32_t, ArpEntry>& table, Logger& logger) : _table(table), _logger(logger)
{
}

bool ArpSpoofingDetector::wants(const Packet& packet) const
{
    //Only check for a VALID arp packet
    return packet.eth && packet.arp && ntohs(packet.eth->ether_type) == ETHERTYPE_ARP;
}
