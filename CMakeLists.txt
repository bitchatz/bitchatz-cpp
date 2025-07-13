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

if(PLATFORM_LINUX)
    CPMAddPackage(
        NAME sdbus-cpp
        GITHUB_REPOSITORY Kistler-Group/sdbus-cpp
        GIT_TAG "7fbfcec455a2af6efe3910baa3089ecba48a9d6d"
        OPTIONS
            "SDBUSCPP_BUILD_LIBSYSTEMD OFF"
            "SDBUSCPP_BUILD_TESTS OFF"
            "SDBUSCPP_BUILD_CODEGEN OFF"
            "SDBUSCPP_BUILD_EXAMPLES OFF"
            "SDBUSCPP_BUILD_DOCS OFF"
            "SDBUSCPP_INSTALL OFF"
            "SDBUSCPP_SDBUS_LIB default"
    )

    CPMAddPackage(
        NAME bluez-dbus-cpp
        GITHUB_REPOSITORY weareaudiofile/bluez-dbus-cpp
        GIT_TAG "257f0a84b49175f3ac21d3f81a38d8a0c6e8e986"
    )
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find Threads
if(PLATFORM_LINUX)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
endif()

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
    set(SOURCES ${SOURCES} src/platforms/apple/bluetooth.mm src/platforms/apple/bluetooth_bridge.mm)
    set_source_files_properties(src/platforms/apple/bluetooth.mm PROPERTIES COMPILE_FLAGS "-x objective-c++")
    set_source_files_properties(src/platforms/apple/bluetooth_bridge.mm PROPERTIES COMPILE_FLAGS "-x objective-c++")
elseif(PLATFORM_LINUX)
    set(SOURCES ${SOURCES} src/platforms/linux/bluetooth.cpp src/platforms/linux/bluetooth_factory.cpp)
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
elseif(PLATFORM_LINUX)
    target_link_libraries(bitchat
        bluez-dbus-cpp
        sdbus-c++
        Threads::Threads
        ${BLUEZ_LIBRARIES}
    )
    target_include_directories(bitchat PRIVATE
        ${BLUEZ_INCLUDE_DIRS}
        ${bluez-dbus-cpp_SOURCE_DIR}/include
        ${sdbus-cpp_SOURCE_DIR}/src
    )
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
