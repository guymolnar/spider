#pragma once

#include "Packet.hpp"

enum class Verdict
{
    ALLOW,
    DROP
};

class Responder
{
public:
    Verdict respond(bool attackDetected, Source source) const;
};