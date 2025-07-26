#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bitchat/core/bitchat_manager.h"
#include "bitchat/helpers/user_interface_helper.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/message_service.h"
#include "bitchat/services/network_service.h"
#include "bitchat/services/noise_service.h"
#include "bitchat/ui/console_ui.h"
#include "mock/bluetooth_announce_runner_mock.h"
#include "mock/bluetooth_interface_dummy.h"
#include "mock/cleanup_runner_mock.h"

#include <chrono>
#include <iostream>
#include <memory>
#include <sstream>

using namespace bitchat;
using namespace ::testing;

class UserInterfaceHelperTest : public Test
{
protected:
    void SetUp() override
    {
        // Services
        auto bluetoothNetwork = std::make_shared<DummyBluetoothNetwork>();
        auto networkService = std::make_shared<NetworkService>();
        auto messageService = std::make_shared<MessageService>();
        auto cryptoService = std::make_shared<CryptoService>();
        auto noiseService = std::make_shared<NoiseService>();
        auto announceRunner = std::make_shared<MockBluetoothAnnounceRunner>();
        auto cleanupRunner = std::make_shared<MockCleanupRunner>();
        auto userInterface = std::make_shared<bitchat::ConsoleUserInterface>();

        // Manager
        auto manager = BitchatManager::shared();
        manager->initialize(userInterface, bluetoothNetwork, networkService, messageService, cryptoService, noiseService, announceRunner, cleanupRunner);
        manager->start();
    }

    void TearDown() override
    {
        BitchatManager::shared().reset();
    }
};

// ============================================================================
// Tests for showChatMessage method
// ============================================================================

TEST_F(UserInterfaceHelperTest, ShowChatMessage_SimpleMessage_DoesNotThrow)
{
    ::testing::internal::CaptureStdout();

    // Test that showChatMessage works without throwing
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessage("Test message"));

    ::testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, ShowChatMessage_WithFormatting_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessage with formatting works
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessage("Hello {}!", "World"));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, ShowChatMessage_WithMultipleArguments_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessage with multiple arguments works
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessage("User {} sent message: {}", "Alice", "Hello there"));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, ShowChatMessage_WithNumbers_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessage with numbers works
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessage("Message count: {}", 42));

    testing::internal::GetCapturedStdout();
}

// ============================================================================
// Tests for showChatMessageInfo method
// ============================================================================

TEST_F(UserInterfaceHelperTest, ShowChatMessageInfo_SimpleMessage_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessageInfo works without throwing
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("Info message"));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, ShowChatMessageInfo_WithFormatting_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessageInfo with formatting works
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("Connection established with {}", "192.168.1.100"));

    testing::internal::GetCapturedStdout();
}

// ============================================================================
// Tests for showChatMessageWarn method
// ============================================================================

TEST_F(UserInterfaceHelperTest, ShowChatMessageWarn_SimpleMessage_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessageWarn works without throwing
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageWarn("Warning message"));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, ShowChatMessageWarn_WithFormatting_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessageWarn with formatting works
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageWarn("Connection timeout after {} seconds", 30));

    testing::internal::GetCapturedStdout();
}

// ============================================================================
// Tests for showChatMessageError method
// ============================================================================

TEST_F(UserInterfaceHelperTest, ShowChatMessageError_SimpleMessage_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessageError works without throwing
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageError("Error message"));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, ShowChatMessageError_WithFormatting_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessageError with formatting works
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageError("Failed to connect to {}: {}", "server.com", "Connection refused"));

    testing::internal::GetCapturedStdout();
}

// ============================================================================
// Tests for showChatMessageSuccess method
// ============================================================================

TEST_F(UserInterfaceHelperTest, ShowChatMessageSuccess_SimpleMessage_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessageSuccess works without throwing
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageSuccess("Success message"));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, ShowChatMessageSuccess_WithFormatting_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test that showChatMessageSuccess with formatting works
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageSuccess("Message sent successfully to {} users", 5));

    testing::internal::GetCapturedStdout();
}

// ============================================================================
// Tests for complex formatting scenarios
// ============================================================================

TEST_F(UserInterfaceHelperTest, ComplexFormatting_WithMultipleTypes_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test complex formatting with multiple types
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("User {} (ID: {}) sent message '{}' at timestamp {}", "Alice", 12345, "Hello world!", 1673789425000));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, ComplexFormatting_WithSpecialCharacters_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test formatting with special characters
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageWarn("Path contains special chars: {}", "C:\\Users\\Alice\\Documents\\file.txt"));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, ComplexFormatting_WithUnicode_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test formatting with unicode characters
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("User name: {}", "José María"));

    testing::internal::GetCapturedStdout();
}

// ============================================================================
// Tests for multiple logging calls
// ============================================================================

TEST_F(UserInterfaceHelperTest, MultipleLoggingCalls_WorkCorrectly)
{
    testing::internal::CaptureStdout();

    // Test multiple logging calls work without issues
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("First message"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageWarn("Second message"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageError("Third message"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageSuccess("Fourth message"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessage("Fifth message"));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, MultipleLoggingCalls_WithFormatting_WorkCorrectly)
{
    testing::internal::CaptureStdout();

    // Test multiple logging calls with formatting
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("User {} connected", "Alice"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageWarn("Connection quality: {}%", 85));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageError("Failed to send message: {}", "Network error"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageSuccess("Message delivered to {} recipients", 3));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessage("Chat session active for {} minutes", 15));

    testing::internal::GetCapturedStdout();
}

// ============================================================================
// Tests for edge cases
// ============================================================================

TEST_F(UserInterfaceHelperTest, EmptyMessage_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test empty message
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo(""));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, MessageWithOnlyPlaceholders_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test message with only placeholders
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("{}", "test"));

    testing::internal::GetCapturedStdout();
}

TEST_F(UserInterfaceHelperTest, MessageWithNoPlaceholders_DoesNotThrow)
{
    testing::internal::CaptureStdout();

    // Test message with no placeholders
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("Simple message with no placeholders"));

    testing::internal::GetCapturedStdout();
}

// ============================================================================
// Performance tests
// ============================================================================

TEST_F(UserInterfaceHelperTest, Performance_MultipleLoggingCalls)
{
    testing::internal::CaptureStdout();

    const int iterations = 100;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i)
    {
        EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("Performance test message {}", i));
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Should complete 100 calls in reasonable time (less than 1ms per call on average)
    EXPECT_LT(duration.count(), iterations * 1000);

    testing::internal::GetCapturedStdout();
}

// ============================================================================
// Integration tests
// ============================================================================

TEST_F(UserInterfaceHelperTest, Integration_AllMethodsWorkTogether)
{
    testing::internal::CaptureStdout();

    // Test that all methods work together in a realistic scenario
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("Chat application started"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessage("Welcome to BitChat!"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("User {} connected from {}", "Alice", "192.168.1.100"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageWarn("Connection quality is {}%", 85));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageSuccess("Message sent successfully"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageError("Failed to send message: {}", "Network timeout"));
    EXPECT_NO_THROW(UserInterfaceHelper::showChatMessageInfo("User {} disconnected", "Alice"));

    testing::internal::GetCapturedStdout();
}
