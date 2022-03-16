cmake_minimum_required(VERSION 3.10)
project(SigScan)

set(CMAKE_CXX_STANDARD 17)
set(Boost_USE_STATIC_LIBS ON)

find_package(Boost COMPONENTS program_options REQUIRED)

set(SRCS src/main.cpp src/SigScan.cpp)
set(LIBS Boost::program_options)

add_executable(${PROJECT_NAME} ${SRCS})
target_link_libraries(${PROJECT_NAME} ${LIBS})

if (NOT APPLE)
    add_executable(${PROJECT_NAME}_static ${SRCS})
    target_link_libraries(${PROJECT_NAME}_static -static ${LIBS})
endif()
