#pragma once

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <net/ethernet.h>
#include <thread>
#include <unordered_map>
#include <vector>

#include "PacketCounter.hpp"

enum class ArpStatus
{
    Pending,    // probe sent, collecting answers
    Trusted     // exactly one mac answered
};

struct ArpEntry
{
    ArpStatus status;
    std::array<uint8_t, ETH_ALEN> mac;                    // the real mac, valid once trusted
    std::chrono::steady_clock::time_point deadline;       // when to decide, used while pending
    std::vector<std::array<uint8_t, ETH_ALEN>> answers;   // every mac that answered the probe
    std::chrono::steady_clock::time_point lastAlert; 
};

class StateManager
{
public:
    StateManager(std::chrono::steady_clock::duration cleanupInterval = std::chrono::seconds(1));
    ~StateManager();

    StateManager(const StateManager&) = delete;
    StateManager& operator=(const StateManager&) = delete;

    PacketCounter& makeCounter(std::chrono::steady_clock::duration window);
    std::unordered_map<uint32_t, ArpEntry>& arpTable();

    void startCleanup();                                     // launch the cleanup thread
    void stopCleanup();                                      // wake it and join; safe to call twice

private:
    void cleanupLoop();

    std::chrono::steady_clock::duration _interval;
    std::vector<std::unique_ptr<PacketCounter>> _counters;   // unique_ptr: counters can't be moved
    std::unordered_map<uint32_t, ArpEntry> _arpTable;        // ip -> entry
    std::thread _cleanupThread;                                 // runs cleanupLoop()

    std::mutex _mutex;                                // guards _counters and _stopping
    std::condition_variable _stopCv;                  // lets stop() wake the thread mid-sleep
    bool _stopRequested = false;
};
