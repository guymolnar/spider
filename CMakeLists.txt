cmake_minimum_required(VERSION 3.16)
project(spider CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(NFQ REQUIRED IMPORTED_TARGET libnetfilter_queue)
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
find_package(Threads REQUIRED)

add_executable(spider
    src/main.cpp
    src/NfqCapture.cpp
    src/PcapCapture.cpp
    src/Parserhow.cpp
)

target_include_directories(spider PRIVATE include)
target_compile_options(spider PRIVATE -Wall -Wextra)
target_link_libraries(spider PRIVATE
    PkgConfig::NFQ
    PkgConfig::PCAP
    Threads::Threads
)