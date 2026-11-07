#include "Logger.hpp"

Logger::Logger(const std::string& filePath) : _file(filePath, std::ios::app)
{
    if(!_file)
    {
        throw std::runtime_error("Logger: cannot open " + filePath);
    }
    _writer = std::thread(&Logger::writerLoop, this);
}