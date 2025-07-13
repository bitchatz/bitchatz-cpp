cmake_minimum_required(VERSION 3.30)
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
    NAME uuid
    GITHUB_REPOSITORY rkg82/uuid-v4
    GIT_TAG dd2f75c027d033586e9eb62b484748cb4bfc515d
)

CPMAddPackage(
    NAME spdlog
    GITHUB_REPOSITORY gabime/spdlog
    VERSION 1.15.3
)

CPMAddPackage(
    NAME lz4
    GITHUB_REPOSITORY lz4/lz4
    VERSION 1.10.0
)

if (lz4_ADDED)
    add_subdirectory(${lz4_SOURCE_DIR}/build/cmake lz4_build)
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include/platforms
    ${CMAKE_CURRENT_SOURCE_DIR}/platforms
    ${spdlog_SOURCE_DIR}/include
    ${lz4_SOURCE_DIR}/lib
    ${uuid_SOURCE_DIR}/include
)

# Source files
set(SOURCES
    main.cpp
    src/bitchat/protocol/packet_utils.cpp
    src/bitchat/compression/compression_manager.cpp
    src/bitchat/crypto/crypto_manager.cpp
    src/bitchat/protocol/packet_serializer.cpp
    src/bitchat/core/bitchat_manager.cpp
)

# Platform-specific source files
if(PLATFORM_APPLE)
    set(SOURCES ${SOURCES} src/platforms/apple/bluetooth.mm)
    set_source_files_properties(src/platforms/apple/bluetooth.mm PROPERTIES COMPILE_FLAGS "-x objective-c++")
elseif(PLATFORM_LINUX)
    set(SOURCES ${SOURCES} src/platforms/linux/bluetooth.cpp)  
endif()

# Create executable
add_executable(bitchat ${SOURCES})

# Link libraries
target_link_libraries(bitchat
    spdlog::spdlog
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
    # Only compile .mm files as Objective-C++, not the entire target
    # target_compile_options(bitchat PRIVATE -x objective-c++)
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
