cmake_minimum_required(VERSION 3.20)
project(bitchat)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include CPM for dependency management
include(cmake/CPM.cmake)

# Include noise-c configuration
include(cmake/noise-c.cmake)

# Library options
set(BUILD_SHARED_LIBS OFF)
set(BUILD_STATIC_LIBS ON)

# LZ4 options
set(LZ4_BUILD_CLI OFF)
set(LZ4_BUILD_LEGACY_LZ4C OFF)
set(LZ4_BUNDLED_MODE OFF)

# Platform-specific settings
if(APPLE)
    set(PLATFORM_APPLE TRUE)
    find_library(FRAMEWORK_COREBLUETOOTH CoreBluetooth)
    find_library(FRAMEWORK_FOUNDATION Foundation)
    find_library(FRAMEWORK_IOKIT IOKit)
    find_library(FRAMEWORK_COREFOUNDATION CoreFoundation)
elseif(WIN32)
    set(PLATFORM_WINDOWS TRUE)
    # TODO: Add Windows Bluetooth libraries
elseif(UNIX AND NOT APPLE)
    set(PLATFORM_LINUX TRUE)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(BLUEZ REQUIRED bluez)
endif()

# Add dependencies via CPM
CPMAddPackage(
    NAME spdlog
    GITHUB_REPOSITORY gabime/spdlog
    VERSION 1.15.3
)

CPMAddPackage(
    NAME lz4
    GITHUB_REPOSITORY lz4/lz4
    VERSION 1.10.0
    SOURCE_SUBDIR "build/cmake"
)

CPMAddPackage("gh:nlohmann/json@3.12.0")

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Source files
set(SOURCES
    src/main.cpp
    src/bitchat/helpers/protocol_helper.cpp
    src/bitchat/helpers/chat_helper.cpp
    src/bitchat/protocol/packet.cpp
    src/bitchat/protocol/message_padding.cpp
    src/bitchat/protocol/packet_serializer.cpp
    src/bitchat/compression/compression_manager.cpp
    src/bitchat/crypto/crypto_manager.cpp
    src/bitchat/core/bitchat_manager.cpp
    src/bitchat/core/network_manager.cpp
    src/bitchat/core/message_manager.cpp
    src/bitchat/core/identity_manager.cpp
    src/bitchat/noise/noise_protocol.cpp
    src/bitchat/noise/noise_session.cpp
    src/bitchat/identity/identity_models.cpp
)

# Platform-specific source files
if(PLATFORM_APPLE)
    set(SOURCES ${SOURCES} src/platforms/apple/bluetooth_factory.mm src/platforms/apple/bluetooth.mm src/platforms/apple/bluetooth_bridge.mm)

    set_source_files_properties(src/platforms/apple/bluetooth.mm PROPERTIES COMPILE_FLAGS "-x objective-c++")
    set_source_files_properties(src/platforms/apple/bluetooth_bridge.mm PROPERTIES COMPILE_FLAGS "-x objective-c++")
    set_source_files_properties(src/platforms/apple/bluetooth_factory.mm PROPERTIES COMPILE_FLAGS "-x objective-c++")
elseif(PLATFORM_LINUX)
    set(SOURCES ${SOURCES} src/platforms/linux/bluetooth.cpp src/platforms/linux/bluetooth_factory.cpp)
endif()

# Create executable
add_executable(bitchat ${SOURCES})

# Include directories
target_include_directories(bitchat PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor
)

# Link libraries
target_link_libraries(bitchat
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    noise-c
    OpenSSL::SSL
    OpenSSL::Crypto
    lz4_static
)

# Platform-specific linking
if(PLATFORM_APPLE)
    target_link_libraries(bitchat
        ${FRAMEWORK_COREBLUETOOTH}
        ${FRAMEWORK_FOUNDATION}
        ${FRAMEWORK_IOKIT}
        ${FRAMEWORK_COREFOUNDATION}
    )
elseif(PLATFORM_LINUX)
    target_link_libraries(bitchat ${BLUEZ_LIBRARIES})
    target_include_directories(bitchat PRIVATE ${BLUEZ_INCLUDE_DIRS})
endif()

# Compiler-specific flags
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(bitchat PRIVATE -Wall -Wextra -Wpedantic)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(bitchat PRIVATE -Wall -Wextra -Wpedantic)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(bitchat PRIVATE /W4)
endif()

# AddressSanitizer option
option(ENABLE_ASAN "Enable AddressSanitizer" ON)

if(ENABLE_ASAN)
    message(STATUS "Building with AddressSanitizer enabled")
    set(ASAN_FLAGS -fsanitize=address -fno-omit-frame-pointer)
    target_compile_options(bitchat PRIVATE ${ASAN_FLAGS})
    target_link_options(bitchat PRIVATE -fsanitize=address)
endif()

# Install target
install(TARGETS bitchat
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Print configuration info
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
