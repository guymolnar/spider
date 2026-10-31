#pragma once
#include "Packet.hpp"
#include <arpa/inet.h>
class Parser
{
public:
    static bool parse(const uint8_t* data, size_t len, Source source, Packet& out);
private:
    static bool parseEthernet(Packet& p, const uint8_t* data, size_t len);
    static bool parseArp(Packet& p, const uint8_t* data, size_t len);
    static bool parseIpv4(Packet& p, const uint8_t* data, size_t len);
    static bool parseTcp(Packet& p, const uint8_t* data, size_t len);
    static bool parseUdp(Packet& p, const uint8_t* data, size_t len);
    static bool parseIcmp(Packet& p, const uint8_t* data, size_t len);
};