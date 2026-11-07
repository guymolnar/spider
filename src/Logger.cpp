#include "Logger.hpp"

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