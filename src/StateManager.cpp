#include "StateManager.hpp"

StateManager::StateManager(std::chrono::steady_clock::duration cleanupInterval)
    : _interval(cleanupInterval)
{
}

StateManager::~StateManager()
{
    stopCleanup(); 
}

PacketCounter& StateManager::makeCounter(std::chrono::steady_clock::duration window)
{
    std::lock_guard<std::mutex> lock(_mutex);
    _counters.push_back(std::make_unique<PacketCounter>(window));
    return *_counters.back();
}

std::unordered_map<uint32_t, ArpEntry>& StateManager::arpTable()
{
    return _arpTable;
}

void StateManager::startCleanup()
{
    std::lock_guard<std::mutex> lock(_mutex);
    if (_cleanupThread.joinable()) //if is already running
    {
        return;
    }
    _stopRequested = false;
    _cleanupThread = std::thread(&StateManager::cleanupLoop, this);
}

void StateManager::stopCleanup()
{
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _stopRequested = true;
    }
    _stopCv.notify_all();
    if (_cleanupThread.joinable())
    {
        _cleanupThread.join();
    }
}

void StateManager::cleanupLoop()
{
    std::unique_lock<std::mutex> lock(_mutex);
    while (!_stopRequested)
    {
        // Sleeps up to _interval with the mutex released. Returns true early if _stopRequested became true.
        if (_stopCv.wait_for(lock, _interval, [this] { return _stopRequested; }))
        {
            break;
        }

        auto now = std::chrono::steady_clock::now();
        for (auto& counter : _counters)
        {
            counter->clearIdle(now);
        }
    }
}