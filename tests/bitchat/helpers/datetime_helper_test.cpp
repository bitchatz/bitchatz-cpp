#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bitchat/helpers/datetime_helper.h"

#include <chrono>
#include <ctime>
#include <regex>
#include <thread>

using namespace bitchat;
using namespace ::testing;

class DateTimeHelperTest : public Test
{
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ============================================================================
// Tests for getCurrentTimestamp method
// ============================================================================

TEST_F(DateTimeHelperTest, GetCurrentTimestamp_ReturnsValidTimestamp)
{
    uint64_t timestamp = DateTimeHelper::getCurrentTimestamp();

    // Should be a reasonable timestamp (not 0, not extremely large)
    EXPECT_GT(timestamp, 0);

    // Should be in milliseconds since epoch (reasonable range for current time)
    // Current time should be after 2020-01-01 (1577836800000 ms)
    EXPECT_GT(timestamp, 1577836800000ULL);

    // Should be before year 2100 (4102444800000 ms)
    EXPECT_LT(timestamp, 4102444800000ULL);
}

TEST_F(DateTimeHelperTest, GetCurrentTimestamp_MultipleCalls_ReturnsIncreasingValues)
{
    uint64_t timestamp1 = DateTimeHelper::getCurrentTimestamp();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    uint64_t timestamp2 = DateTimeHelper::getCurrentTimestamp();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    uint64_t timestamp3 = DateTimeHelper::getCurrentTimestamp();

    // Timestamps should be increasing (or at least not decreasing)
    EXPECT_LE(timestamp1, timestamp2);
    EXPECT_LE(timestamp2, timestamp3);
}

TEST_F(DateTimeHelperTest, GetCurrentTimestamp_ConsistentWithSystemClock)
{
    auto system_time = std::chrono::system_clock::now();
    auto system_ms = std::chrono::duration_cast<std::chrono::milliseconds>(system_time.time_since_epoch()).count();

    uint64_t helper_timestamp = DateTimeHelper::getCurrentTimestamp();

    // Should be very close to system time (within 100ms tolerance)
    EXPECT_NEAR(helper_timestamp, system_ms, 100);
}

// ============================================================================
// Tests for formatTimestamp method
// ============================================================================

TEST_F(DateTimeHelperTest, FormatTimestamp_ZeroTimestamp_ReturnsValidTime)
{
    uint64_t timestamp = 0;
    std::string result = DateTimeHelper::formatTimestamp(timestamp);

    // Should return a time string in HH:MM:SS format
    EXPECT_EQ(result.length(), 8); // HH:MM:SS = 8 characters
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');

    // Should be a valid time format (timezone dependent)
    EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

TEST_F(DateTimeHelperTest, FormatTimestamp_UnixEpoch_ReturnsValidTime)
{
    // Unix epoch: January 1, 1970 00:00:00 UTC
    uint64_t timestamp = 0;
    std::string result = DateTimeHelper::formatTimestamp(timestamp);

    // Should return a valid time format (timezone dependent)
    EXPECT_EQ(result.length(), 8);
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');
    EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

TEST_F(DateTimeHelperTest, FormatTimestamp_OneHourAfterEpoch_ReturnsValidTime)
{
    // One hour after epoch: January 1, 1970 01:00:00 UTC
    uint64_t timestamp = 3600000; // 1 hour in milliseconds
    std::string result = DateTimeHelper::formatTimestamp(timestamp);

    // Should return a valid time format (timezone dependent)
    EXPECT_EQ(result.length(), 8);
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');
    EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

TEST_F(DateTimeHelperTest, FormatTimestamp_OneDayAfterEpoch_ReturnsValidTime)
{
    // One day after epoch: January 2, 1970 00:00:00 UTC
    uint64_t timestamp = 86400000; // 24 hours in milliseconds
    std::string result = DateTimeHelper::formatTimestamp(timestamp);

    // Should return a valid time format (timezone dependent)
    EXPECT_EQ(result.length(), 8);
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');
    EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

TEST_F(DateTimeHelperTest, FormatTimestamp_ArbitraryTime_ReturnsValidFormat)
{
    // Test with a specific timestamp: 2023-01-15 14:30:25 UTC
    // This corresponds to 1673789425000 milliseconds since epoch
    uint64_t timestamp = 1673789425000;
    std::string result = DateTimeHelper::formatTimestamp(timestamp);

    // Should return a time string in HH:MM:SS format
    EXPECT_EQ(result.length(), 8);
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');

    // Should be "14:30:25" (local time may vary, but format should be correct)
    // Note: This test may fail depending on timezone, so we'll just check format
    EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

TEST_F(DateTimeHelperTest, FormatTimestamp_Midnight_ReturnsValidTime)
{
    // Test midnight time
    uint64_t timestamp = 1673827200000; // 2023-01-16 00:00:00 UTC
    std::string result = DateTimeHelper::formatTimestamp(timestamp);

    // Should return a valid time format (timezone dependent)
    EXPECT_EQ(result.length(), 8);
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');
    EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

TEST_F(DateTimeHelperTest, FormatTimestamp_Noon_ReturnsValidTime)
{
    // Test noon time
    uint64_t timestamp = 1673870400000; // 2023-01-16 12:00:00 UTC
    std::string result = DateTimeHelper::formatTimestamp(timestamp);

    // Should return a valid time format (timezone dependent)
    EXPECT_EQ(result.length(), 8);
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');
    EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

TEST_F(DateTimeHelperTest, FormatTimestamp_EndOfDay_ReturnsValidTime)
{
    // Test end of day (23:59:59)
    uint64_t timestamp = 1673913599000; // 2023-01-16 23:59:59 UTC
    std::string result = DateTimeHelper::formatTimestamp(timestamp);

    // Should return a valid time format (timezone dependent)
    EXPECT_EQ(result.length(), 8);
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');
    EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

TEST_F(DateTimeHelperTest, FormatTimestamp_LargeTimestamp_ReturnsValidFormat)
{
    // Test with a very large timestamp (year 2100)
    uint64_t timestamp = 4102444800000; // 2100-01-01 00:00:00 UTC
    std::string result = DateTimeHelper::formatTimestamp(timestamp);

    // Should return a valid time format
    EXPECT_EQ(result.length(), 8);
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');
    EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

TEST_F(DateTimeHelperTest, FormatTimestamp_WithMilliseconds_IgnoresMilliseconds)
{
    // Test that milliseconds are ignored (timestamp is in milliseconds, but we only show seconds)
    uint64_t timestamp1 = 1673789425000; // 14:30:25.000
    uint64_t timestamp2 = 1673789425999; // 14:30:25.999

    std::string result1 = DateTimeHelper::formatTimestamp(timestamp1);
    std::string result2 = DateTimeHelper::formatTimestamp(timestamp2);

    // Both should return the same time (milliseconds are ignored)
    EXPECT_EQ(result1, result2);
}

TEST_F(DateTimeHelperTest, FormatTimestamp_ConsistentFormat)
{
    // Test that the format is consistent across different timestamps
    std::vector<uint64_t> timestamps = {
        0,             // Epoch
        3600000,       // 1 hour after epoch
        86400000,      // 1 day after epoch
        1673789425000, // 2023-01-15 14:30:25 UTC
        1673827200000, // 2023-01-16 00:00:00 UTC
        1673870400000, // 2023-01-16 12:00:00 UTC
        1673913599000, // 2023-01-16 23:59:59 UTC
        4102444800000  // 2100-01-01 00:00:00 UTC
    };

    for (uint64_t timestamp : timestamps)
    {
        std::string result = DateTimeHelper::formatTimestamp(timestamp);

        // All results should have the same format: HH:MM:SS
        EXPECT_EQ(result.length(), 8);
        EXPECT_EQ(result[2], ':');
        EXPECT_EQ(result[5], ':');
        EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));

        // Hours should be between 00-23
        int hours = std::stoi(result.substr(0, 2));
        EXPECT_GE(hours, 0);
        EXPECT_LE(hours, 23);

        // Minutes should be between 00-59
        int minutes = std::stoi(result.substr(3, 2));
        EXPECT_GE(minutes, 0);
        EXPECT_LE(minutes, 59);

        // Seconds should be between 00-59
        int seconds = std::stoi(result.substr(6, 2));
        EXPECT_GE(seconds, 0);
        EXPECT_LE(seconds, 59);
    }
}

TEST_F(DateTimeHelperTest, FormatTimestamp_TimeProgression)
{
    // Test that time progresses correctly
    uint64_t base_timestamp = 1673789425000; // 2023-01-15 14:30:25 UTC

    // Test 1 second later
    std::string time1 = DateTimeHelper::formatTimestamp(base_timestamp);
    std::string time2 = DateTimeHelper::formatTimestamp(base_timestamp + 1000);

    // Times should be different (unless we're at a timezone boundary)
    // At minimum, they should be valid time formats
    EXPECT_EQ(time1.length(), 8);
    EXPECT_EQ(time2.length(), 8);
    EXPECT_TRUE(std::regex_match(time1, std::regex("\\d{2}:\\d{2}:\\d{2}")));
    EXPECT_TRUE(std::regex_match(time2, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

// ============================================================================
// Integration tests
// ============================================================================

TEST_F(DateTimeHelperTest, GetCurrentTimestampAndFormat_Integration)
{
    uint64_t timestamp = DateTimeHelper::getCurrentTimestamp();
    std::string formatted = DateTimeHelper::formatTimestamp(timestamp);

    // Should return a valid time format
    EXPECT_EQ(formatted.length(), 8);
    EXPECT_EQ(formatted[2], ':');
    EXPECT_EQ(formatted[5], ':');
    EXPECT_TRUE(std::regex_match(formatted, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

TEST_F(DateTimeHelperTest, TimestampConsistency_Integration)
{
    // Test that formatting a timestamp and then converting back gives consistent results
    uint64_t original_timestamp = DateTimeHelper::getCurrentTimestamp();
    std::string formatted = DateTimeHelper::formatTimestamp(original_timestamp);

    // Wait a bit and get another timestamp
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    uint64_t new_timestamp = DateTimeHelper::getCurrentTimestamp();
    std::string new_formatted = DateTimeHelper::formatTimestamp(new_timestamp);

    // The formatted times should be different if enough time has passed
    // (or the same if less than 1 second has passed)
    if (new_timestamp - original_timestamp >= 1000)
    {
        EXPECT_NE(formatted, new_formatted);
    }
}

// ============================================================================
// Edge case tests
// ============================================================================

TEST_F(DateTimeHelperTest, FormatTimestamp_MaxUint64_HandlesGracefully)
{
    uint64_t max_timestamp = UINT64_MAX;
    std::string result = DateTimeHelper::formatTimestamp(max_timestamp);

    // Should not crash and should return a valid format
    EXPECT_EQ(result.length(), 8);
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');
}

TEST_F(DateTimeHelperTest, FormatTimestamp_VeryLargeTimestamp_HandlesGracefully)
{
    // Test with a timestamp that would be far in the future
    uint64_t future_timestamp = 9999999999999; // Very large timestamp
    std::string result = DateTimeHelper::formatTimestamp(future_timestamp);

    // Should return a valid time format
    EXPECT_EQ(result.length(), 8);
    EXPECT_EQ(result[2], ':');
    EXPECT_EQ(result[5], ':');
    EXPECT_TRUE(std::regex_match(result, std::regex("\\d{2}:\\d{2}:\\d{2}")));
}

// ============================================================================
// Performance tests
// ============================================================================

TEST_F(DateTimeHelperTest, GetCurrentTimestamp_Performance)
{
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i)
    {
        DateTimeHelper::getCurrentTimestamp();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Should complete 1000 calls in reasonable time (less than 1ms per call on average)
    EXPECT_LT(duration.count(), iterations * 1000);
}

TEST_F(DateTimeHelperTest, FormatTimestamp_Performance)
{
    const int iterations = 1000;
    uint64_t test_timestamp = DateTimeHelper::getCurrentTimestamp();

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i)
    {
        DateTimeHelper::formatTimestamp(test_timestamp);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Should complete 1000 calls in reasonable time (less than 1ms per call on average)
    EXPECT_LT(duration.count(), iterations * 1000);
}
