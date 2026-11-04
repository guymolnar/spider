#include "PacketCounter.hpp"
#include <stdexcept>

PacketCounter::PacketCounter(std::chrono::steady_clock::duration window) : _bucketWidth(window / kBuckets)
{
    if (_bucketWidth.count() <= 0)
    {
        throw std::invalid_argument("window too small for the bucket count");
    }
}

int64_t PacketCounter::sliceOf(std::chrono::steady_clock::time_point t) const
{
    return t.time_since_epoch() / _bucketWidth;   // whole slices since the clock started
}

void PacketCounter::record(uint32_t srcIp, std::chrono::steady_clock::time_point now)
{
    const int64_t buckets = kBuckets;
    int64_t slice = sliceOf(now);

    auto [it, inserted] = _entries.try_emplace(srcIp);
    Entry& e = it->second;

    if (inserted)
    {
        e.lastSlice = slice;
    }
    else
    {
        int64_t gap = slice - e.lastSlice;
        if (gap >= buckets)                 // silent for a whole window
        {
            for (int i = 0; i < kBuckets; ++i)
            {
                e.buckets[i] = 0;
            }
        }
        else
        {
            for (int64_t s = e.lastSlice + 1; s <= slice; ++s)
            {
                e.buckets[s % buckets] = 0; // buckets we are entering get wiped
            }
        }
        e.lastSlice = slice;
    }

    e.buckets[slice % buckets]++;
}
