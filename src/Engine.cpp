#include "Engine.hpp"
#include "IcmpFloodDetector.hpp"
#include "Parser.hpp"

#include <chrono>


Engine::Engine()
{
    _detectors.push_back(std::make_unique<IcmpFloodDetector>(_state.makeCounter(std::chrono::seconds(1)), 100));
    _state.startCleanup();
}

Engine::~Engine()
{
    _state.stopCleanup();
}

Verdict Engine::process(const uint8_t* data, size_t len, Source source) const
{
    Packet pkt;
    if (!Parser::parse(data, len, source, pkt))
    {
        return Verdict::ALLOW;
    }

    Verdict result = Verdict::ALLOW;
    for (const auto& detector : _detectors)
    {
        if (detector->wants(pkt) && detector->inspect(pkt) == Verdict::DROP)
        {
            result = Verdict::DROP;
        }
    }
    return result;
}