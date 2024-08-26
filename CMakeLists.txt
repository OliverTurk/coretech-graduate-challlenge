cmake_minimum_required(VERSION 3.10)

project(PacketProcessor VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "Architecture" FORCE)

# Manually specify paths
include_directories(/opt/homebrew/include)  # Adjust this path based on your installation
link_directories(/opt/homebrew/lib)         # Adjust this path based on your installation

# Source files
file(GLOB SOURCES "src/*.cpp")

# Add executable
add_executable(PacketProcessor ${SOURCES})

# Link libraries
target_link_libraries(PacketProcessor PRIVATE pcap)

# Include directories for the target
target_include_directories(PacketProcessor PRIVATE include)

# Optionally specify compile features
target_compile_features(PacketProcessor PRIVATE cxx_std_17)
