# Test source files
set(TEST_SOURCES
    ${COMMON_SOURCES}
    ${CMAKE_CURRENT_SOURCE_DIR}/bitchat/core/bitchat_manager_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/bitchat/helpers/string_helper_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/bitchat/helpers/protocol_helper_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/bitchat/helpers/datetime_helper_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/bitchat/helpers/user_interface_helper_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mock/bluetooth_interface_dummy.cpp
)

# Create test executable
add_executable(bitchat_tests ${TEST_SOURCES})

# Include directories
target_include_directories(bitchat_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/vendor
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/tests
)

# Link libraries
target_link_libraries(bitchat_tests
    ${COMMON_LIBRARIES}
    GTest::gtest_main
    GTest::gmock_main
)

# Apply compiler flags
apply_compiler_flags(bitchat_tests)

# AddressSanitizer
if(ENABLE_ASAN)
    target_compile_options(bitchat_tests PRIVATE ${ASAN_FLAGS})
    target_link_options(bitchat_tests PRIVATE -fsanitize=address)
endif()

# Add tests
add_test(NAME bitchat_tests COMMAND bitchat_tests)

# Enable CTest integration with Google Test
include(GoogleTest)
gtest_discover_tests(bitchat_tests)
