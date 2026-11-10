#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <unordered_map>

class PacketCounter
{
public:
    static constexpr int kBuckets = 5;
/*
    Q: Why do we need "buckets" and not just use a single counter that we reset every second?
    A: The problem: Imagine we use a single variable that just resets at every second, 
    with a threshold of 100 packet per second.
    if a source sends 90 packets in the second half of some second, 
    and then 90 more packets in the first half of the next second,
    we would have a total of 180 packets in a single second, more than the threshold allows, but our counter 
    resets midway so it cant accurately count the number of packets in a second.

    To solve this problem, we use a sliding (circular) array, each cell representing a "bucket", each bucket
    is a time slice (window / num of buckets). When we record a packet, we increment the counter in the matching bucket
    (matching bucket means the bucket that corresponds to the current time slice), and we zero out outdated 
    buckets (buckets whose value is not from the last window)
    and when we want to get the rate, we sum all the buckets. This way, we can more accurately count the number of packets in a second.

    Its important to note that even with this approach, we still have a margin of error.
    Imagine the window edge falls in the middle of the oldest bucket, some of its packets are inside the window
    and some are outside, but the bucket only stores a count so we cant tell which is which.
    We have to either count the whole bucket or drop it, and we drop it. This gives us a margin of error
    of about 1 bucket width (for example if the window is 1 second and we have 5 buckets, the margin of error is 20%), which is acceptable to us.
*/
    explicit PacketCounter(std::chrono::steady_clock::duration window);

    PacketCounter(const PacketCounter&) = delete;
    PacketCounter& operator=(const PacketCounter&) = delete;

    void record(uint32_t srcIp, std::chrono::steady_clock::time_point now);

    uint32_t rate(uint32_t srcIp, std::chrono::steady_clock::time_point now) const;

    void clearIdle(std::chrono::steady_clock::time_point now);

private:
    struct Entry
    {
        
        std::array<uint32_t, kBuckets> buckets{};
        int64_t lastSlice = 0;           
    };

    int64_t sliceOf(std::chrono::steady_clock::time_point t) const; 

    std::chrono::steady_clock::duration _bucketWidth;          
    std::unordered_map<uint32_t, Entry> _entries;
    mutable std::mutex _mutex;
};