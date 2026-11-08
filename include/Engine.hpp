#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "Detector.hpp"
#include "Packet.hpp"
#include "StateManager.hpp"
#include "Responder.hpp"

class Logger;

class Engine
{
public:
    Engine(Logger& logger);
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    Verdict process(const uint8_t* data, size_t len, Source source) const;

private:
    StateManager _state;                    // declared first, so it is destroyed last
    std::vector<std::unique_ptr<Detector>> _detectors;
    Responder _responder;
};