#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bitchat/helpers/protocol_helper.h"

using namespace bitchat;
using namespace ::testing;

class ProtocolHelperTest : public Test
{
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ============================================================================
// Tests for isValidPeerID method
// ============================================================================

TEST_F(ProtocolHelperTest, IsValidPeerID_EmptyString_ReturnsFalse)
{
    std::string peerID = "";
    EXPECT_FALSE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_TooShort_ReturnsFalse)
{
    std::string peerID = "1234567890abcde"; // 15 characters
    EXPECT_FALSE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_TooLong_ReturnsFalse)
{
    std::string peerID = "1234567890abcdef1"; // 17 characters
    EXPECT_FALSE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_ValidLength_ValidHex_ReturnsTrue)
{
    std::string peerID = "1234567890abcdef"; // 16 characters, valid hex
    EXPECT_TRUE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_ValidLength_UpperCaseHex_ReturnsTrue)
{
    std::string peerID = "ABCDEF1234567890"; // 16 characters, uppercase hex
    EXPECT_TRUE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_ValidLength_MixedCaseHex_ReturnsTrue)
{
    std::string peerID = "aBcDeF1234567890"; // 16 characters, mixed case hex
    EXPECT_TRUE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_ValidLength_AllZeros_ReturnsTrue)
{
    std::string peerID = "0000000000000000"; // 16 zeros
    EXPECT_TRUE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_ValidLength_AllFs_ReturnsTrue)
{
    std::string peerID = "ffffffffffffffff"; // 16 f's
    EXPECT_TRUE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_ValidLength_NonHexCharacters_ReturnsFalse)
{
    std::string peerID = "1234567890abcdefg"; // 16 characters, but 'g' is not hex
    EXPECT_FALSE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_ValidLength_SpecialCharacters_ReturnsFalse)
{
    std::string peerID = "1234567890abc@ef"; // 16 characters, but '@' is not hex
    EXPECT_FALSE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_ValidLength_Spaces_ReturnsFalse)
{
    std::string peerID = "1234567890abc ef"; // 16 characters, but space is not hex
    EXPECT_FALSE(ProtocolHelper::isValidPeerID(peerID));
}

// ============================================================================
// Tests for isValidChannelName method
// ============================================================================

TEST_F(ProtocolHelperTest, IsValidChannelName_EmptyString_ReturnsFalse)
{
    std::string channel = "";
    EXPECT_FALSE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_DoesNotStartWithHash_ReturnsFalse)
{
    std::string channel = "general";
    EXPECT_FALSE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_ValidCharacters_ReturnsTrue)
{
    std::string channel = "#general";
    EXPECT_TRUE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_WithUnderscores_ReturnsTrue)
{
    std::string channel = "#general_chat";
    EXPECT_TRUE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_WithHyphens_ReturnsTrue)
{
    std::string channel = "#general-chat";
    EXPECT_TRUE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_WithNumbers_ReturnsTrue)
{
    std::string channel = "#general123";
    EXPECT_TRUE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_MixedValidCharacters_ReturnsTrue)
{
    std::string channel = "#general-chat_123";
    EXPECT_TRUE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_OnlyHash_ReturnsTrue)
{
    std::string channel = "#";
    EXPECT_TRUE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_WithSpaces_ReturnsFalse)
{
    std::string channel = "#general chat";
    EXPECT_FALSE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_WithSpecialCharacters_ReturnsFalse)
{
    std::string channel = "#general@chat";
    EXPECT_FALSE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_WithPunctuation_ReturnsFalse)
{
    std::string channel = "#general.chat";
    EXPECT_FALSE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_TooLong_ReturnsFalse)
{
    // Create a channel name that's 51 characters long (exceeds 50 limit)
    std::string channel = "#" + std::string(50, 'a');
    EXPECT_FALSE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_MaximumLength_ReturnsTrue)
{
    // Create a channel name that's exactly 50 characters long
    std::string channel = "#" + std::string(49, 'a');
    EXPECT_TRUE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_WithUppercase_ReturnsTrue)
{
    std::string channel = "#GENERAL";
    EXPECT_TRUE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_StartsWithHash_WithMixedCase_ReturnsTrue)
{
    std::string channel = "#GeneralChat";
    EXPECT_TRUE(ProtocolHelper::isValidChannelName(channel));
}

// ============================================================================
// Tests for isValidNickname method
// ============================================================================

TEST_F(ProtocolHelperTest, IsValidNickname_EmptyString_ReturnsFalse)
{
    std::string nickname = "";
    EXPECT_FALSE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_ValidAlphanumeric_ReturnsTrue)
{
    std::string nickname = "alice123";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_WithUnderscores_ReturnsTrue)
{
    std::string nickname = "alice_123";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_WithHyphens_ReturnsTrue)
{
    std::string nickname = "alice-123";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_MixedValidCharacters_ReturnsTrue)
{
    std::string nickname = "Alice_123-Chat";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_OnlyLetters_ReturnsTrue)
{
    std::string nickname = "Alice";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_OnlyNumbers_ReturnsTrue)
{
    std::string nickname = "12345";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_OnlyUnderscores_ReturnsTrue)
{
    std::string nickname = "___";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_OnlyHyphens_ReturnsTrue)
{
    std::string nickname = "---";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_WithSpaces_ReturnsFalse)
{
    std::string nickname = "alice 123";
    EXPECT_FALSE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_WithSpecialCharacters_ReturnsFalse)
{
    std::string nickname = "alice@123";
    EXPECT_FALSE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_WithPunctuation_ReturnsFalse)
{
    std::string nickname = "alice.123";
    EXPECT_FALSE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_TooLong_ReturnsFalse)
{
    // Create a nickname that's 33 characters long (exceeds 32 limit)
    std::string nickname = std::string(33, 'a');
    EXPECT_FALSE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_MaximumLength_ReturnsTrue)
{
    // Create a nickname that's exactly 32 characters long
    std::string nickname = std::string(32, 'a');
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_WithUppercase_ReturnsTrue)
{
    std::string nickname = "ALICE123";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_WithMixedCase_ReturnsTrue)
{
    std::string nickname = "Alice123";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_SingleCharacter_ReturnsTrue)
{
    std::string nickname = "a";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_SingleNumber_ReturnsTrue)
{
    std::string nickname = "1";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_SingleUnderscore_ReturnsTrue)
{
    std::string nickname = "_";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidNickname_SingleHyphen_ReturnsTrue)
{
    std::string nickname = "-";
    EXPECT_TRUE(ProtocolHelper::isValidNickname(nickname));
}

// ============================================================================
// Edge case tests
// ============================================================================

TEST_F(ProtocolHelperTest, IsValidPeerID_UnicodeCharacters_ReturnsFalse)
{
    std::string peerID = "1234567890abcdeñ"; // 16 characters, but 'ñ' is not hex
    EXPECT_FALSE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_UnicodeCharacters_ReturnsFalse)
{
    std::string channel = "#generalñchat";
    EXPECT_FALSE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidNickname_UnicodeCharacters_ReturnsFalse)
{
    std::string nickname = "aliceñ123";
    EXPECT_FALSE(ProtocolHelper::isValidNickname(nickname));
}

TEST_F(ProtocolHelperTest, IsValidPeerID_ControlCharacters_ReturnsFalse)
{
    // Create a string with control characters using vector
    std::vector<char> chars = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', '\0', 'e', 'f'};
    std::string peerID(chars.begin(), chars.end());
    EXPECT_FALSE(ProtocolHelper::isValidPeerID(peerID));
}

TEST_F(ProtocolHelperTest, IsValidChannelName_ControlCharacters_ReturnsFalse)
{
    // Create a string with control characters using vector
    std::vector<char> chars = {'#', 'g', 'e', 'n', 'e', 'r', 'a', 'l', '\0', 'c', 'h', 'a', 't'};
    std::string channel(chars.begin(), chars.end());
    EXPECT_FALSE(ProtocolHelper::isValidChannelName(channel));
}

TEST_F(ProtocolHelperTest, IsValidNickname_ControlCharacters_ReturnsFalse)
{
    // Create a string with control characters using vector
    std::vector<char> chars = {'a', 'l', 'i', 'c', 'e', '\0', '1', '2', '3'};
    std::string nickname(chars.begin(), chars.end());
    EXPECT_FALSE(ProtocolHelper::isValidNickname(nickname));
}
