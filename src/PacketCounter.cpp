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
    return t.time_since_epoch() / _bucketWidth;   // whole slices since the clock started (Doesnt matter whats the start point because later we check for differences)
}

void PacketCounter::record(uint32_t srcIp, std::chrono::steady_clock::time_point now)
{
    const int64_t buckets = kBuckets; //amount of buckets (cells in the array)
    int64_t slice = sliceOf(now); //getting current slice (whole slices since the clock started)

    std::lock_guard<std::mutex> lock(_mutex);
    auto [it, inserted] = _entries.try_emplace(srcIp); //checking if src ip exists in the map, if not create new entry
    Entry& e = it->second;

    if (inserted)
    {
        e.lastSlice = slice; //if we just created the entry, set the last slice to the current slice
    }
    else
    {
        if (slice < e.lastSlice)
        {
            /*current slice can never be smaller than the last slice (chronologicaly doesnt make sense), 
        but because of threads it may happen, so we just ignore it and use the last slice*/
            slice = e.lastSlice;
        }
        int64_t gap = slice - e.lastSlice; //checking the gap (amount of slices) that passed since the last slice
        if (gap >= buckets)
        {
        //if gap is bigger than the amount of buckets, it was silent for a whole window so the entire array is outdated, so we zero it
            for (int i = 0; i < kBuckets; ++i)
            {
                e.buckets[i] = 0;
            }
        }
        else //if gap is smaller than the amount of buckets, we just zero the buckets that are outdated (even though there may be none)
        {
            for (int64_t s = e.lastSlice + 1; s <= slice; s++)
            {
                e.buckets[s % buckets] = 0; //any slice between the last slice and the current slice got no packets, so we zero it
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
    if (it == _entries.end()) // if ip has no entry, his rate is 0;
    {
        return 0;
    }

    const Entry& e = it->second;
    uint32_t total = 0;
    for (int64_t age = 0; age < buckets; age++) //age is used as a counter to count age slices before last slice
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