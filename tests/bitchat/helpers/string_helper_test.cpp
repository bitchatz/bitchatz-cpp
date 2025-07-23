#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bitchat/helpers/string_helper.h"

using namespace bitchat;
using namespace ::testing;

class StringHelperTest : public Test
{
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ============================================================================
// Tests for toHex method
// ============================================================================

TEST_F(StringHelperTest, ToHex_EmptyVector_ReturnsEmptyString)
{
    std::vector<uint8_t> data;
    std::string result = StringHelper::toHex(data);
    EXPECT_EQ(result, "");
}

TEST_F(StringHelperTest, ToHex_SingleByte_ReturnsCorrectHex)
{
    std::vector<uint8_t> data = {0x0A};
    std::string result = StringHelper::toHex(data);
    EXPECT_EQ(result, "0a");
}

TEST_F(StringHelperTest, ToHex_MultipleBytes_ReturnsCorrectHex)
{
    std::vector<uint8_t> data = {0x00, 0xFF, 0x1A, 0xB2};
    std::string result = StringHelper::toHex(data);
    EXPECT_EQ(result, "00ff1ab2");
}

TEST_F(StringHelperTest, ToHex_ZeroBytes_ReturnsCorrectHex)
{
    std::vector<uint8_t> data = {0x00, 0x00, 0x00};
    std::string result = StringHelper::toHex(data);
    EXPECT_EQ(result, "000000");
}

TEST_F(StringHelperTest, ToHex_MaxBytes_ReturnsCorrectHex)
{
    std::vector<uint8_t> data = {0xFF, 0xFF, 0xFF};
    std::string result = StringHelper::toHex(data);
    EXPECT_EQ(result, "ffffff");
}

// ============================================================================
// Tests for stringToVector method
// ============================================================================

TEST_F(StringHelperTest, StringToVector_EmptyString_ReturnsEmptyVector)
{
    std::string str = "";
    std::vector<uint8_t> result = StringHelper::stringToVector(str);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringHelperTest, StringToVector_OddLengthString_ReturnsEmptyVector)
{
    std::string str = "123";
    std::vector<uint8_t> result = StringHelper::stringToVector(str);
    EXPECT_TRUE(result.empty());
}

TEST_F(StringHelperTest, StringToVector_SingleByte_ReturnsCorrectVector)
{
    std::string str = "0a";
    std::vector<uint8_t> result = StringHelper::stringToVector(str);
    std::vector<uint8_t> expected = {0x0A};
    EXPECT_EQ(result, expected);
}

TEST_F(StringHelperTest, StringToVector_MultipleBytes_ReturnsCorrectVector)
{
    std::string str = "00ff1ab2";
    std::vector<uint8_t> result = StringHelper::stringToVector(str);
    std::vector<uint8_t> expected = {0x00, 0xFF, 0x1A, 0xB2};
    EXPECT_EQ(result, expected);
}

TEST_F(StringHelperTest, StringToVector_UpperCaseHex_ReturnsCorrectVector)
{
    std::string str = "00FF1AB2";
    std::vector<uint8_t> result = StringHelper::stringToVector(str);
    std::vector<uint8_t> expected = {0x00, 0xFF, 0x1A, 0xB2};
    EXPECT_EQ(result, expected);
}

TEST_F(StringHelperTest, StringToVector_ZeroBytes_ReturnsCorrectVector)
{
    std::string str = "000000";
    std::vector<uint8_t> result = StringHelper::stringToVector(str);
    std::vector<uint8_t> expected = {0x00, 0x00, 0x00};
    EXPECT_EQ(result, expected);
}

// ============================================================================
// Tests for vectorToString method
// ============================================================================

TEST_F(StringHelperTest, VectorToString_EmptyVector_ReturnsEmptyString)
{
    std::vector<uint8_t> vec;
    std::string result = StringHelper::vectorToString(vec);
    EXPECT_EQ(result, "");
}

TEST_F(StringHelperTest, VectorToString_SingleByte_ReturnsCorrectString)
{
    std::vector<uint8_t> vec = {0x41}; // ASCII 'A'
    std::string result = StringHelper::vectorToString(vec);
    EXPECT_EQ(result, "A");
}

TEST_F(StringHelperTest, VectorToString_MultipleBytes_ReturnsCorrectString)
{
    std::vector<uint8_t> vec = {0x48, 0x65, 0x6C, 0x6C, 0x6F}; // "Hello"
    std::string result = StringHelper::vectorToString(vec);
    EXPECT_EQ(result, "Hello");
}

TEST_F(StringHelperTest, VectorToString_ZeroBytes_ReturnsCorrectString)
{
    std::vector<uint8_t> vec = {0x00, 0x00, 0x00};
    std::string result = StringHelper::vectorToString(vec);
    EXPECT_EQ(result, std::string(3, '\0'));
}

TEST_F(StringHelperTest, VectorToString_MixedBytes_ReturnsCorrectString)
{
    std::vector<uint8_t> vec = {0x48, 0x00, 0x6C, 0x6C, 0x6F}; // "H\0llo"
    std::string result = StringHelper::vectorToString(vec);

    // Check length (should include null character)
    EXPECT_EQ(result.length(), 5);

    // Check individual characters
    EXPECT_EQ(result[0], 'H');
    EXPECT_EQ(result[1], '\0');
    EXPECT_EQ(result[2], 'l');
    EXPECT_EQ(result[3], 'l');
    EXPECT_EQ(result[4], 'o');
}

// ============================================================================
// Tests for normalizePeerID method
// ============================================================================

TEST_F(StringHelperTest, NormalizePeerID_EmptyString_ReturnsEmptyString)
{
    std::string peerID = "";
    std::string result = StringHelper::normalizePeerID(peerID);
    EXPECT_EQ(result, "");
}

TEST_F(StringHelperTest, NormalizePeerID_NoNullChars_ReturnsSameString)
{
    std::string peerID = "test123";
    std::string result = StringHelper::normalizePeerID(peerID);
    EXPECT_EQ(result, "test123");
}

TEST_F(StringHelperTest, NormalizePeerID_WithNullChars_RemovesNullChars)
{
    // Create a string with null characters using vector
    std::vector<uint8_t> vec = {'t', 'e', 's', 't', '\0', '\0', '\0', '1', '2', '3'};
    std::string peerID = StringHelper::vectorToString(vec);
    std::string result = StringHelper::normalizePeerID(peerID);
    EXPECT_EQ(result, "test123");
}

TEST_F(StringHelperTest, NormalizePeerID_OnlyNullChars_ReturnsEmptyString)
{
    // Create a string with only null characters using vector
    std::vector<uint8_t> vec = {'\0', '\0', '\0', '\0'};
    std::string peerID = StringHelper::vectorToString(vec);
    std::string result = StringHelper::normalizePeerID(peerID);
    EXPECT_EQ(result, "");
}

TEST_F(StringHelperTest, NormalizePeerID_NullCharsAtEnd_RemovesNullChars)
{
    // Create a string with null characters at the end using vector
    std::vector<uint8_t> vec = {'t', 'e', 's', 't', '1', '2', '3', '\0', '\0', '\0'};
    std::string peerID = StringHelper::vectorToString(vec);
    std::string result = StringHelper::normalizePeerID(peerID);
    EXPECT_EQ(result, "test123");
}

TEST_F(StringHelperTest, NormalizePeerID_NullCharsAtStart_RemovesNullChars)
{
    // Create a string with null characters at the start using vector
    std::vector<uint8_t> vec = {'\0', '\0', '\0', 't', 'e', 's', 't', '1', '2', '3'};
    std::string peerID = StringHelper::vectorToString(vec);
    std::string result = StringHelper::normalizePeerID(peerID);
    EXPECT_EQ(result, "test123");
}

// ============================================================================
// Tests for randomPeerID method
// ============================================================================

TEST_F(StringHelperTest, RandomPeerID_ReturnsValidHexString)
{
    std::string result = StringHelper::randomPeerID();

    // Should be 16 characters (8 bytes * 2 hex chars per byte)
    EXPECT_EQ(result.length(), 16);

    // Should contain only hex characters
    // clang-format off
    EXPECT_TRUE(std::all_of(result.begin(), result.end(), [](char c) {
        return std::isxdigit(c);
    }));
    // clang-format on
}

TEST_F(StringHelperTest, RandomPeerID_MultipleCalls_ReturnsDifferentIDs)
{
    std::string id1 = StringHelper::randomPeerID();
    std::string id2 = StringHelper::randomPeerID();
    std::string id3 = StringHelper::randomPeerID();

    // Should be different (very unlikely to be the same)
    EXPECT_NE(id1, id2);
    EXPECT_NE(id2, id3);
    EXPECT_NE(id1, id3);

    // All should be valid hex strings
    EXPECT_EQ(id1.length(), 16);
    EXPECT_EQ(id2.length(), 16);
    EXPECT_EQ(id3.length(), 16);
}

// ============================================================================
// Tests for uuidv4 method
// ============================================================================

TEST_F(StringHelperTest, Uuidv4_ReturnsValidUUID)
{
    std::string result = StringHelper::uuidv4();

    // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    // where x is any hex digit and y is one of 8, 9, A, or B
    EXPECT_EQ(result.length(), 36); // 32 hex chars + 4 hyphens

    // Check format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    EXPECT_EQ(result[8], '-');
    EXPECT_EQ(result[13], '-');
    EXPECT_EQ(result[18], '-');
    EXPECT_EQ(result[23], '-');
    EXPECT_EQ(result[14], '4'); // Version 4

    // Check that y is one of 8, 9, A, or B
    char y = result[19];
    EXPECT_TRUE(y == '8' || y == '9' || y == 'a' || y == 'b' || y == 'A' || y == 'B');

    // All other characters should be hex digits
    std::string hexPart = result.substr(0, 8) + result.substr(9, 4) + result.substr(14, 4) + result.substr(19, 4) + result.substr(24, 12);

    // clang-format off
    EXPECT_TRUE(std::all_of(hexPart.begin(), hexPart.end(), [](char c) {
        return std::isxdigit(c);
    }));
    // clang-format on
}

TEST_F(StringHelperTest, Uuidv4_MultipleCalls_ReturnsDifferentUUIDs)
{
    std::string uuid1 = StringHelper::uuidv4();
    std::string uuid2 = StringHelper::uuidv4();
    std::string uuid3 = StringHelper::uuidv4();

    // Should be different (very unlikely to be the same)
    EXPECT_NE(uuid1, uuid2);
    EXPECT_NE(uuid2, uuid3);
    EXPECT_NE(uuid1, uuid3);
}

// ============================================================================
// Tests for randomNickname method
// ============================================================================

TEST_F(StringHelperTest, RandomNickname_ReturnsValidFormat)
{
    std::string result = StringHelper::randomNickname();

    // Should start with "anon"
    EXPECT_TRUE(result.substr(0, 4) == "anon");

    // Should be "anon" + 4 digits
    EXPECT_EQ(result.length(), 8); // "anon" (4) + 4 digits

    // Last 4 characters should be digits
    std::string digits = result.substr(4);

    // clang-format off
    EXPECT_TRUE(std::all_of(digits.begin(), digits.end(), [](char c) {
        return std::isdigit(c);
    }));
    // clang-format on

    // Should be between 1000 and 9999
    int number = std::stoi(digits);
    EXPECT_GE(number, 1000);
    EXPECT_LE(number, 9999);
}

TEST_F(StringHelperTest, RandomNickname_MultipleCalls_ReturnsDifferentNicknames)
{
    std::string nick1 = StringHelper::randomNickname();
    std::string nick2 = StringHelper::randomNickname();
    std::string nick3 = StringHelper::randomNickname();

    // Should be different (very unlikely to be the same)
    EXPECT_NE(nick1, nick2);
    EXPECT_NE(nick2, nick3);
    EXPECT_NE(nick1, nick3);

    // All should have valid format
    EXPECT_TRUE(nick1.substr(0, 4) == "anon");
    EXPECT_TRUE(nick2.substr(0, 4) == "anon");
    EXPECT_TRUE(nick3.substr(0, 4) == "anon");
}

// ============================================================================
// Integration tests
// ============================================================================

TEST_F(StringHelperTest, ToHexAndStringToVector_RoundTrip)
{
    std::vector<uint8_t> original = {0x00, 0xFF, 0x1A, 0xB2, 0x7F, 0xE3};
    std::string hex = StringHelper::toHex(original);
    std::vector<uint8_t> converted = StringHelper::stringToVector(hex);
    EXPECT_EQ(original, converted);
}

TEST_F(StringHelperTest, VectorToStringAndBack_RoundTrip)
{
    std::string original = "Hello World!";
    std::vector<uint8_t> vec = StringHelper::stringToVector(StringHelper::toHex(std::vector<uint8_t>(original.begin(), original.end())));
    std::string converted = StringHelper::vectorToString(vec);
    EXPECT_EQ(original, converted);
}
