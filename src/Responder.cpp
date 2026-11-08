#include "Responder.hpp"

Verdict Responder::respond(bool attackDetected, Source source) const
{
    if (attackDetected && source == Source::Inline)
    {
        return Verdict::DROP;
    }

    return Verdict::ALLOW;
}