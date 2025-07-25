#pragma once

#include <chrono>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace bitchat
{
namespace protocol
{

// Protocol Constants

struct BitchatProtocolConstants
{
    static constexpr uint8_t protocolVersion = 1;
    static constexpr size_t maxMessageSize = 65535;
    static constexpr size_t maxChannelNameLength = 32;
    static constexpr size_t maxNicknameLength = 32;
    static constexpr size_t maxPeerIdLength = 64;
    static constexpr std::chrono::seconds messageTimeout{30};
    static constexpr std::chrono::seconds handshakeTimeout{60};
    static constexpr std::chrono::seconds peerTimeout{300}; // 5 minutes
};

// Message Types

enum class BitchatMessageType : uint8_t
{
    Handshake = 0x01,
    HandshakeResponse = 0x02,
    Message = 0x03,
    ChannelJoin = 0x04,
    ChannelLeave = 0x05,
    PeerInfo = 0x06,
    ChannelKeyShare = 0x07,
    KeepAlive = 0x08,
    Error = 0x09
};

// Error Codes

enum class BitchatErrorCode : uint16_t
{
    None = 0x0000,
    InvalidMessage = 0x0001,
    HandshakeFailed = 0x0002,
    AuthenticationFailed = 0x0003,
    ChannelNotFound = 0x0004,
    ChannelAccessDenied = 0x0005,
    MessageTooLarge = 0x0006,
    RateLimitExceeded = 0x0007,
    SessionExpired = 0x0008,
    InternalError = 0x0009,
    UnsupportedVersion = 0x000A,
    InvalidPeerID = 0x000B,
    InvalidChannelName = 0x000C
};

// Base Message

struct BitchatMessage
{
    uint8_t version;
    BitchatMessageType type;
    std::string peerID;
    std::chrono::system_clock::time_point timestamp;
    std::vector<uint8_t> payload;

    virtual nlohmann::json toJson() const;
    virtual void fromJson(const nlohmann::json &json);

    virtual ~BitchatMessage() = default;
};

// Handshake Message

struct BitchatHandshakeMessage : public BitchatMessage
{
    std::string nickname;
    std::string channel;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> handshakeData;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json &json) override;
};

// Handshake Response Message

struct BitchatHandshakeResponseMessage : public BitchatMessage
{
    std::string nickname;
    std::string channel;
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> handshakeData;
    BitchatErrorCode errorCode;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json &json) override;
};

// Chat Message

struct BitchatChatMessage : public BitchatMessage
{
    std::string nickname;
    std::string channel;
    std::string content;
    std::vector<uint8_t> encryptedContent;
    bool isEncrypted;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json &json) override;
};

// Channel Join Message

struct BitchatChannelJoinMessage : public BitchatMessage
{
    std::string nickname;
    std::string channel;
    std::vector<uint8_t> channelKey;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json &json) override;
};

// Channel Leave Message

struct BitchatChannelLeaveMessage : public BitchatMessage
{
    std::string nickname;
    std::string channel;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json &json) override;
};

// Peer Info Message

struct BitchatPeerInfoMessage : public BitchatMessage
{
    std::string nickname;
    std::string channel;
    std::chrono::system_clock::time_point lastSeen;
    int rssi;
    std::vector<uint8_t> fingerprint;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json &json) override;
};

// Channel Key Share Message

struct BitchatChannelKeyShareMessage : public BitchatMessage
{
    std::string channel;
    std::vector<uint8_t> encryptedKeyData;
    std::string creatorFingerprint;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json &json) override;
};

// Keep Alive Message

struct BitchatKeepAliveMessage : public BitchatMessage
{
    std::string nickname;
    std::string channel;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json &json) override;
};

// Error Message

struct BitchatErrorMessage : public BitchatMessage
{
    BitchatErrorCode errorCode;
    std::string errorMessage;
    std::optional<std::string> originalMessageId;

    nlohmann::json toJson() const override;
    void fromJson(const nlohmann::json &json) override;
};

// Message Factory

class BitchatMessageFactory
{
public:
    static std::shared_ptr<BitchatMessage> createMessage(BitchatMessageType type);
    static std::shared_ptr<BitchatMessage> parseMessage(const std::vector<uint8_t> &data);
    static std::vector<uint8_t> serializeMessage(const BitchatMessage &message);

private:
    static std::shared_ptr<BitchatMessage> createMessageFromJson(const nlohmann::json &json);
};

// Protocol Validator

class BitchatProtocolValidator
{
public:
    static bool validateMessage(const BitchatMessage &message);
    static bool validateHandshakeMessage(const BitchatHandshakeMessage &message);
    static bool validateChatMessage(const BitchatChatMessage &message);
    static bool validateChannelName(const std::string &channel);
    static bool validateNickname(const std::string &nickname);
    static bool validatePeerID(const std::string &peerID);
    static bool validateMessageSize(const std::vector<uint8_t> &payload);

private:
    static bool validateTimestamp(const std::chrono::system_clock::time_point &timestamp);
};

// Protocol Utils

namespace protocol_utils
{
std::string messageTypeToString(BitchatMessageType type);
BitchatMessageType messageTypeFromString(const std::string &type);
std::string errorCodeToString(BitchatErrorCode code);
BitchatErrorCode errorCodeFromString(const std::string &code);
std::string generateMessageId();
std::chrono::system_clock::time_point getCurrentTimestamp();
bool isMessageExpired(const BitchatMessage &message,
                      std::chrono::seconds timeout = BitchatProtocolConstants::messageTimeout);
} // namespace protocol_utils

} // namespace protocol
} // namespace bitchat
