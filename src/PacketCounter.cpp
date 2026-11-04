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

    std::lock_guard<std::mutex> lock(_mutex);
    auto [it, inserted] = _entries.try_emplace(srcIp);
    Entry& e = it->second;

    if (inserted)
    {
        e.lastSlice = slice;
    }
    else
    {
        if (slice < e.lastSlice)            // a packet stamped earlier arrived late; never go backwards
        {
            slice = e.lastSlice;
        }
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

uint32_t PacketCounter::rate(uint32_t srcIp, std::chrono::steady_clock::time_point now) const
{
    const int64_t buckets = kBuckets;
    int64_t nowSlice = sliceOf(now); //current slice

    std::lock_guard<std::mutex> lock(_mutex);
    auto it = _entries.find(srcIp);
    if (it == _entries.end())
    {
        return 0;
    }

    const Entry& e = it->second;
    uint32_t total = 0;
    for (int64_t age = 0; age < buckets; age++)
    {
        int64_t s = e.lastSlice - age;      // the slice this bucket holds
        if (s > nowSlice - buckets && s >= 0)   // still inside the window ending now
        {
            total += e.buckets[s % buckets];
        }
    }
    return total;
}

void PacketCounter::clearIdle(std::chrono::steady_clock::time_point now)
{
    const int64_t buckets = kBuckets;
    int64_t nowSlice = sliceOf(now);

    std::lock_guard<std::mutex> lock(_mutex);
    for (auto it = _entries.begin(); it != _entries.end();)
    {
        if (nowSlice - buckets >= it->second.lastSlice)
        {
            it = _entries.erase(it);        // erase returns the next iterator
        }
        else
        {
            it++;
        }
    }
}