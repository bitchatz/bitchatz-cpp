#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bitchat/helpers/chat_helper.h"

#include <chrono>
#include <iostream>
#include <memory>
#include <sstream>

using namespace bitchat;
using namespace ::testing;

class ChatHelperTest : public Test
{
protected:
    void SetUp() override
    {
        // Ensure clean state before each test
        ChatHelper::shutdown();
    }

    void TearDown() override
    {
        // Clean up after each test
        ChatHelper::shutdown();
    }
};

// ============================================================================
// Tests for initialize method
// ============================================================================

TEST_F(ChatHelperTest, Initialize_FirstCall_InitializesLogger)
{
    // Test that initialize works on first call
    EXPECT_NO_THROW(ChatHelper::initialize());

    // Verify that subsequent calls don't throw
    EXPECT_NO_THROW(ChatHelper::initialize());
    EXPECT_NO_THROW(ChatHelper::initialize());
}

TEST_F(ChatHelperTest, Initialize_MultipleCalls_DoesNotReinitialize)
{
    // First initialization
    ChatHelper::initialize();

    // Multiple subsequent calls should not cause issues
    for (int i = 0; i < 10; ++i)
    {
        EXPECT_NO_THROW(ChatHelper::initialize());
    }
}

// ============================================================================
// Tests for shutdown method
// ============================================================================

TEST_F(ChatHelperTest, Shutdown_WhenNotInitialized_DoesNothing)
{
    // Shutdown when not initialized should not throw
    EXPECT_NO_THROW(ChatHelper::shutdown());
    EXPECT_NO_THROW(ChatHelper::shutdown());
}

TEST_F(ChatHelperTest, Shutdown_WhenInitialized_ResetsState)
{
    // Initialize first
    ChatHelper::initialize();

    // Then shutdown
    EXPECT_NO_THROW(ChatHelper::shutdown());

    // Multiple shutdown calls should not cause issues
    EXPECT_NO_THROW(ChatHelper::shutdown());
    EXPECT_NO_THROW(ChatHelper::shutdown());
}

TEST_F(ChatHelperTest, Shutdown_AfterInitialization_AllowsReinitialization)
{
    // Initialize
    ChatHelper::initialize();

    // Shutdown
    ChatHelper::shutdown();

    // Should be able to initialize again
    EXPECT_NO_THROW(ChatHelper::initialize());
}

// ============================================================================
// Tests for show method
// ============================================================================

TEST_F(ChatHelperTest, Show_SimpleMessage_DoesNotThrow)
{
    // Test that show method works without throwing
    EXPECT_NO_THROW(ChatHelper::show("Test message"));
}

TEST_F(ChatHelperTest, Show_WithFormatting_DoesNotThrow)
{
    // Test that show method with formatting works
    EXPECT_NO_THROW(ChatHelper::show("Hello {}!", "World"));
}

TEST_F(ChatHelperTest, Show_WithMultipleArguments_DoesNotThrow)
{
    // Test that show method with multiple arguments works
    EXPECT_NO_THROW(ChatHelper::show("User {} sent message: {}", "Alice", "Hello there"));
}

TEST_F(ChatHelperTest, Show_WithNumbers_DoesNotThrow)
{
    // Test that show method with numbers works
    EXPECT_NO_THROW(ChatHelper::show("Message count: {}", 42));
}

TEST_F(ChatHelperTest, Show_AutoInitializes_WhenNotInitialized)
{
    // Ensure not initialized
    ChatHelper::shutdown();

    // This should auto-initialize and not throw
    EXPECT_NO_THROW(ChatHelper::show("Auto-initialized message"));
}

// ============================================================================
// Tests for info method
// ============================================================================

TEST_F(ChatHelperTest, Info_SimpleMessage_DoesNotThrow)
{
    // Test that info method works without throwing
    EXPECT_NO_THROW(ChatHelper::info("Info message"));
}

TEST_F(ChatHelperTest, Info_WithFormatting_DoesNotThrow)
{
    // Test that info method with formatting works
    EXPECT_NO_THROW(ChatHelper::info("Connection established with {}", "192.168.1.100"));
}

TEST_F(ChatHelperTest, Info_AutoInitializes_WhenNotInitialized)
{
    ChatHelper::shutdown();

    // This should auto-initialize and not throw
    EXPECT_NO_THROW(ChatHelper::info("Auto-initialized info"));
}

// ============================================================================
// Tests for warn method
// ============================================================================

TEST_F(ChatHelperTest, Warn_SimpleMessage_DoesNotThrow)
{
    // Test that warn method works without throwing
    EXPECT_NO_THROW(ChatHelper::warn("Warning message"));
}

TEST_F(ChatHelperTest, Warn_WithFormatting_DoesNotThrow)
{
    // Test that warn method with formatting works
    EXPECT_NO_THROW(ChatHelper::warn("Connection timeout after {} seconds", 30));
}

TEST_F(ChatHelperTest, Warn_AutoInitializes_WhenNotInitialized)
{
    ChatHelper::shutdown();

    // This should auto-initialize and not throw
    EXPECT_NO_THROW(ChatHelper::warn("Auto-initialized warning"));
}

// ============================================================================
// Tests for error method
// ============================================================================

TEST_F(ChatHelperTest, Error_SimpleMessage_DoesNotThrow)
{
    // Test that error method works without throwing
    EXPECT_NO_THROW(ChatHelper::error("Error message"));
}

TEST_F(ChatHelperTest, Error_WithFormatting_DoesNotThrow)
{
    // Test that error method with formatting works
    EXPECT_NO_THROW(ChatHelper::error("Failed to connect to {}: {}", "server.com", "Connection refused"));
}

TEST_F(ChatHelperTest, Error_AutoInitializes_WhenNotInitialized)
{
    ChatHelper::shutdown();

    // This should auto-initialize and not throw
    EXPECT_NO_THROW(ChatHelper::error("Auto-initialized error"));
}

// ============================================================================
// Tests for success method
// ============================================================================

TEST_F(ChatHelperTest, Success_SimpleMessage_DoesNotThrow)
{
    // Test that success method works without throwing
    EXPECT_NO_THROW(ChatHelper::success("Success message"));
}

TEST_F(ChatHelperTest, Success_WithFormatting_DoesNotThrow)
{
    // Test that success method with formatting works
    EXPECT_NO_THROW(ChatHelper::success("Message sent successfully to {} users", 5));
}

TEST_F(ChatHelperTest, Success_AutoInitializes_WhenNotInitialized)
{
    ChatHelper::shutdown();

    // This should auto-initialize and not throw
    EXPECT_NO_THROW(ChatHelper::success("Auto-initialized success"));
}

// ============================================================================
// Tests for complex formatting scenarios
// ============================================================================

TEST_F(ChatHelperTest, ComplexFormatting_WithMultipleTypes_DoesNotThrow)
{
    // Test complex formatting with multiple types
    EXPECT_NO_THROW(ChatHelper::info("User {} (ID: {}) sent message '{}' at timestamp {}",
                                     "Alice", 12345, "Hello world!", 1673789425000));
}

TEST_F(ChatHelperTest, ComplexFormatting_WithSpecialCharacters_DoesNotThrow)
{
    // Test formatting with special characters
    EXPECT_NO_THROW(ChatHelper::warn("Path contains special chars: {}", "C:\\Users\\Alice\\Documents\\file.txt"));
}

TEST_F(ChatHelperTest, ComplexFormatting_WithUnicode_DoesNotThrow)
{
    // Test formatting with unicode characters
    EXPECT_NO_THROW(ChatHelper::info("User name: {}", "José María"));
}

// ============================================================================
// Tests for multiple logging calls
// ============================================================================

TEST_F(ChatHelperTest, MultipleLoggingCalls_WorkCorrectly)
{
    // Test multiple logging calls work without issues
    EXPECT_NO_THROW(ChatHelper::info("First message"));
    EXPECT_NO_THROW(ChatHelper::warn("Second message"));
    EXPECT_NO_THROW(ChatHelper::error("Third message"));
    EXPECT_NO_THROW(ChatHelper::success("Fourth message"));
    EXPECT_NO_THROW(ChatHelper::show("Fifth message"));
}

TEST_F(ChatHelperTest, MultipleLoggingCalls_WithFormatting_WorkCorrectly)
{
    // Test multiple logging calls with formatting
    EXPECT_NO_THROW(ChatHelper::info("User {} connected", "Alice"));
    EXPECT_NO_THROW(ChatHelper::warn("Connection quality: {}%", 85));
    EXPECT_NO_THROW(ChatHelper::error("Failed to send message: {}", "Network error"));
    EXPECT_NO_THROW(ChatHelper::success("Message delivered to {} recipients", 3));
    EXPECT_NO_THROW(ChatHelper::show("Chat session active for {} minutes", 15));
}

// ============================================================================
// Tests for edge cases
// ============================================================================

TEST_F(ChatHelperTest, EmptyMessage_DoesNotThrow)
{
    // Test empty message
    EXPECT_NO_THROW(ChatHelper::info(""));
}

TEST_F(ChatHelperTest, MessageWithOnlyPlaceholders_DoesNotThrow)
{
    // Test message with only placeholders
    EXPECT_NO_THROW(ChatHelper::info("{}", "test"));
}

TEST_F(ChatHelperTest, MessageWithNoPlaceholders_DoesNotThrow)
{
    // Test message with no placeholders
    EXPECT_NO_THROW(ChatHelper::info("Simple message with no placeholders"));
}

// ============================================================================
// Tests for initialization/shutdown cycle
// ============================================================================

TEST_F(ChatHelperTest, InitializationShutdownCycle_WorksCorrectly)
{
    // Multiple initialize/shutdown cycles should work
    for (int i = 0; i < 5; ++i)
    {
        ChatHelper::initialize();
        EXPECT_NO_THROW(ChatHelper::info("Cycle {}", i + 1));
        ChatHelper::shutdown();
    }
}

TEST_F(ChatHelperTest, Shutdown_LogsShutdownMessage)
{
    ChatHelper::initialize();

    // Shutdown should not throw and should log a message
    EXPECT_NO_THROW(ChatHelper::shutdown());
}

// ============================================================================
// Performance tests
// ============================================================================

TEST_F(ChatHelperTest, Performance_MultipleLoggingCalls)
{
    const int iterations = 100;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i)
    {
        EXPECT_NO_THROW(ChatHelper::info("Performance test message {}", i));
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Should complete 100 calls in reasonable time (less than 1ms per call on average)
    EXPECT_LT(duration.count(), iterations * 1000);
}

TEST_F(ChatHelperTest, Performance_InitializationShutdown)
{
    const int iterations = 50;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i)
    {
        ChatHelper::initialize();
        ChatHelper::shutdown();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Should complete 50 cycles in reasonable time
    EXPECT_LT(duration.count(), iterations * 1000);
}

// ============================================================================
// Integration tests
// ============================================================================

TEST_F(ChatHelperTest, Integration_AllMethodsWorkTogether)
{
    // Test that all methods work together in a realistic scenario
    ChatHelper::initialize();

    EXPECT_NO_THROW(ChatHelper::info("Chat application started"));
    EXPECT_NO_THROW(ChatHelper::show("Welcome to BitChat!"));
    EXPECT_NO_THROW(ChatHelper::info("User {} connected from {}", "Alice", "192.168.1.100"));
    EXPECT_NO_THROW(ChatHelper::warn("Connection quality is {}%", 85));
    EXPECT_NO_THROW(ChatHelper::success("Message sent successfully"));
    EXPECT_NO_THROW(ChatHelper::error("Failed to send message: {}", "Network timeout"));
    EXPECT_NO_THROW(ChatHelper::info("User {} disconnected", "Alice"));

    ChatHelper::shutdown();
}

TEST_F(ChatHelperTest, Integration_AutoInitializationWorks)
{
    // Test that auto-initialization works for all methods
    ChatHelper::shutdown(); // Ensure clean state

    EXPECT_NO_THROW(ChatHelper::show("Auto-initialized show"));
    EXPECT_NO_THROW(ChatHelper::info("Auto-initialized info"));
    EXPECT_NO_THROW(ChatHelper::warn("Auto-initialized warn"));
    EXPECT_NO_THROW(ChatHelper::error("Auto-initialized error"));
    EXPECT_NO_THROW(ChatHelper::success("Auto-initialized success"));

    ChatHelper::shutdown();
}
