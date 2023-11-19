cmake_minimum_required(VERSION 3.22.1)

project(FinvestHoldings LANGUAGES C)

set(BUILD_SHARED_LIBS OFF)
set(CMAKE_C_STANDARD 17)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# Enable compiler warnings.
set(CMAKE_C_FLAGS "-Wall -Wextra")
# Use debug symbols, skip compiler optimizations, and define DEBUG for use in
# C files.
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
# Level 3 optimizations.
set(CMAKE_C_FLAGS_RELEASE "-O3")

list(APPEND CMAKE_CTEST_ARGUMENTS "--output-on-failure")

add_subdirectory("src")
enable_testing()
add_subdirectory("test")
