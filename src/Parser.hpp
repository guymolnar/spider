#pragma once
#include "Packet.hpp"

class Parser
{
public:
    static bool parse(const uint8_t* data, size_t len);
private:
    static bool parseEthernet(const uint8_t* data, size_t len);
    static bool parseArp(const uint8_t* data, size_t len);
    static bool parseIpv4(const uint8_t* data, size_t len);
    static bool parseTcp(const uint8_t* data, size_t len);
    static bool parseUdp(const uint8_t* data, size_t len);
    static bool parseIcmp(const uint8_t* data, size_t len);
};