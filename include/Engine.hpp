#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "Detector.hpp"
#include "Packet.hpp"
#include "PacketSender.hpp"
#include "StateManager.hpp"
#include "Responder.hpp"

class Logger;

class Engine
{
public:
    Engine(Logger& logger, const std::string& lanIface, uint32_t routerIp);   // routerIp in network order
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    Verdict process(const uint8_t* data, size_t len, Source source) const;

private:
    StateManager _state;                    // declared first, so it is destroyed last
    PacketSender _sender;                   // detectors hold a reference, so it must outlive them
    std::vector<std::unique_ptr<Detector>> _detectors;
    Responder _responder;
};