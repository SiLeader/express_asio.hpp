cmake_minimum_required(VERSION 3.21)
project(express_asio_hpp)

set(CMAKE_CXX_STANDARD 17)

set(Boost_USE_MULTITHREADED ON)
find_package(Boost REQUIRED COMPONENTS date_time system log)

add_executable(express_asio_hpp main.cc express_asio.hpp)
target_include_directories(express_asio_hpp PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(express_asio_hpp Boost::date_time Boost::system Boost::log)
