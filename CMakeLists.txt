cmake_minimum_required(VERSION 3.20)
project(bitchat)

# General settings
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Testing option
option(ENABLE_ASAN "Enable Address Sanitizer" OFF)
option(ENABLE_TESTS "Build tests" OFF)

if(ENABLE_TESTS)
    enable_testing()
endif()

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include CPM for dependency management
include(cmake/CPM.cmake)

# Include custom functions
include(cmake/functions.cmake)

# Include noise-c configuration
include(cmake/noise-c.cmake)

# Include lz4 configuration
include(cmake/lz4.cmake)

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

CPMAddPackage("gh:nlohmann/json@3.12.0")

# Add Google Test only if tests are enabled
if(ENABLE_TESTS)
    CPMAddPackage("gh:google/googletest@1.17.0")
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Common libraries
set(COMMON_LIBRARIES
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    noise-c
    lz4
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Source files
set(COMMON_SOURCES
    ${CMAKE_SOURCE_DIR}/src/bitchat/core/bitchat_data.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/core/bitchat_manager.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/helpers/chat_helper.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/helpers/compression_helper.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/helpers/datetime_helper.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/helpers/noise_helper.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/helpers/protocol_helper.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/helpers/string_helper.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/identity/identity_models.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/noise/noise_hybrid_key_exchange.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/noise/noise_post_quantum_key_exchange.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/noise/noise_protocol.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/noise/noise_protocol_migration.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/noise/noise_pq_handshake_pattern.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/noise/noise_security_error.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/noise/noise_session_default.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/protocol/message_padding.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/protocol/packet_serializer.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/protocol/packet.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/runners/bluetooth_announce_runner.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/runners/cleanup_runner.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/services/crypto_service.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/services/identity_service.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/services/message_service.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/services/network_service.cpp
    ${CMAKE_SOURCE_DIR}/src/bitchat/services/noise_service.cpp
)

set(SOURCES
    src/main.cpp
    ${COMMON_SOURCES}
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
target_link_libraries(bitchat ${COMMON_LIBRARIES})

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

# Apply compiler flags to main executable
apply_compiler_flags(bitchat)

# AddressSanitizer option
if(ENABLE_ASAN)
    message(STATUS "Building with AddressSanitizer enabled")
    set(ASAN_FLAGS -fsanitize=address -fno-omit-frame-pointer)
    target_compile_options(bitchat PRIVATE ${ASAN_FLAGS})
    target_link_options(bitchat PRIVATE -fsanitize=address)
endif()

if(ENABLE_TESTS)
    add_subdirectory(tests)
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
message(STATUS "Testing enabled: ${ENABLE_TESTS}")

# CPack configuration
include(cmake/cpack.cmake)
