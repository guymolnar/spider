#pragma once
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>

class Logger {
public:
    Logger(const std::string& filePath);
    ~Logger();

    void log(const std::string& message);

private:
    void writerLoop();

    static constexpr std::size_t MAX_QUEUE_SIZE = 10000;

    std::ofstream _file_;
    std::deque<std::string> _queue;
    std::mutex _mutex;
    std::condition_variable _cv;
    bool _running = true;       // guarded by mutex_
    std::size_t _dropped = 0;   // guarded by mutex_
    std::thread _writer;        // started last, after everything it uses
};