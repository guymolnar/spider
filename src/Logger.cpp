#include "Logger.hpp"

#include <chrono>
#include <ctime>
#include <stdexcept>

Logger::Logger(const std::string& filePath) : _file(filePath, std::ios::app)
{
    if(!_file)
    {
        throw std::runtime_error("Logger: cannot open " + filePath);
    }
    _writer = std::thread(&Logger::writerLoop, this);
}

Logger::~Logger() {
    {
        std::lock_guard<std::mutex> lock(_mutex);
        _running = false;
    }
    _cv.notify_one();
    _writer.join();
}

static std::string timestamp() {
    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
    localtime_r(&now, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

void Logger::log(const std::string& message) {
    std::string line = "[" + timestamp() + "] " + message;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        if (_queue.size() >= MAX_QUEUE_SIZE)
        {
            _dropped++;
            return;
        }
        _queue.push_back(line);
    }
    _cv.notify_one();
}

void Logger::writerLoop() {
    while (true) {
        std::deque<std::string> batch;
        std::size_t dropped = 0;
        {
            std::unique_lock<std::mutex> lock(_mutex);
            _cv.wait(lock, [this] { return !_queue.empty() || !_running; });
            if (_queue.empty() && !_running)
            {
                return;
            }
            batch.swap(_queue);
            dropped = _dropped;
            _dropped = 0;
        }

        for (const std::string& line : batch) {
            _file << line << '\n';
        }
        if (dropped > 0)
        {
            _file << "[" << timestamp() << "] logger: " << dropped << " log lines dropped (queue full)\n";
        }
        _file.flush();
    }
}
