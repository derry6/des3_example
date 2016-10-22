cmake_minimum_required(VERSION 2.8)
project(des3_example)

add_definitions(-DDES3_DEBUG)
include_directories(${CMAKE_SOURCE_DIR})
add_executable(des3_example DES3Helper.cpp DES3Example.cpp)
target_link_libraries(des3_example crypto)
