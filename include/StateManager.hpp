#pragma once

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "PacketCounter.hpp"

class StateManager
{
public:
    StateManager(std::chrono::steady_clock::duration cleanupInterval = std::chrono::seconds(1));
    ~StateManager();

    StateManager(const StateManager&) = delete;
    StateManager& operator=(const StateManager&) = delete;

    PacketCounter& makeCounter(std::chrono::steady_clock::duration window);

    void startCleanup();                                     // launch the cleanup thread
    void stopCleanup();                                      // wake it and join; safe to call twice

private:
    void cleanupLoop();

    std::chrono::steady_clock::duration _interval;
    std::vector<std::unique_ptr<PacketCounter>> _counters;   // unique_ptr: counters can't be moved
    std::thread _cleanupThread;                                 // runs cleanupLoop()

    std::mutex _mutex;                                // guards _counters and _stopping
    std::condition_variable _stopCv;                  // lets stop() wake the thread mid-sleep
    bool _stopRequested = false;
};