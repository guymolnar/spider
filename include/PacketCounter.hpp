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
    static constexpr std::size_t kBuckets = 5;

    PacketCounter(std::chrono::steady_clock::duration window);

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
   
};