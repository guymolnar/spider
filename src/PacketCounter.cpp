#include "PacketCounter.hpp"
#include <stdexcept>

PacketCounter::PacketCounter(std::chrono::steady_clock::duration window) : _bucketWidth(window / kBuckets)
{
    if (_bucketWidth.count() <= 0)
    {
        throw std::invalid_argument("window too small for the bucket count");
    }
}