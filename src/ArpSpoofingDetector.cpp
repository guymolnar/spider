#include "ArpSpoofingDetector.hpp"

ArpSpoofingDetector::ArpSpoofingDetector(std::unordered_map<uint32_t, uint32_t> ipToMacTable, Logger& logger) : _ipToMacTable(ipToMacTable), _logger(logger)
{
}