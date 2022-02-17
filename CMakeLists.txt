cmake_minimum_required(VERSION 3.16)
project(SigScan)

set(CMAKE_CXX_STANDARD 17)

find_package(Boost COMPONENTS program_options REQUIRED)

add_executable(SigScan src/main.cpp src/SigScan.cpp)
target_link_libraries(SigScan Boost::program_options)
