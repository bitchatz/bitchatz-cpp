#pragma once

#include "bitchat_protocol.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace bitchat
{
namespace protocol
{

// Binary Protocol Constants

struct BinaryProtocolConstants
{
    static constexpr uint8_t magicByte = 0xBC; // Bitchat
    static constexpr uint8_t currentVersion = 1;
    static constexpr size_t headerSize = 8;
    static constexpr size_t maxPacketSize = 65535;
    static constexpr size_t maxMessageSize = 65527; // maxPacketSize - headerSize
};

// Binary Packet Header

struct BinaryPacketHeader
{
    uint8_t magic;
    uint8_t version;
    uint16_t payloadLength;
    uint16_t messageType;
    uint16_t checksum;

    bool isValid() const;
    uint16_t computeChecksum(const std::vector<uint8_t> &payload) const;
    std::vector<uint8_t> serialize() const;
    static BinaryPacketHeader deserialize(const std::vector<uint8_t> &data);
};

// Binary Protocol

class BinaryProtocol
{
public:
    // Serialization

    /// Serialize a message to binary format
    static std::vector<uint8_t> serializeMessage(const BitchatMessage &message);

    /// Deserialize a message from binary format
    static std::shared_ptr<BitchatMessage> deserializeMessage(const std::vector<uint8_t> &data);

    /// Serialize handshake message
    static std::vector<uint8_t> serializeHandshakeMessage(const BitchatHandshakeMessage &message);

    /// Deserialize handshake message
    static std::shared_ptr<BitchatHandshakeMessage> deserializeHandshakeMessage(const std::vector<uint8_t> &data);

    /// Serialize handshake response message
    static std::vector<uint8_t> serializeHandshakeResponseMessage(const BitchatHandshakeResponseMessage &message);

    /// Deserialize handshake response message
    static std::shared_ptr<BitchatHandshakeResponseMessage> deserializeHandshakeResponseMessage(const std::vector<uint8_t> &data);

    /// Serialize chat message
    static std::vector<uint8_t> serializeChatMessage(const BitchatChatMessage &message);

    /// Deserialize chat message
    static std::shared_ptr<BitchatChatMessage> deserializeChatMessage(const std::vector<uint8_t> &data);

    /// Serialize channel join message
    static std::vector<uint8_t> serializeChannelJoinMessage(const BitchatChannelJoinMessage &message);

    /// Deserialize channel join message
    static std::shared_ptr<BitchatChannelJoinMessage> deserializeChannelJoinMessage(const std::vector<uint8_t> &data);

    /// Serialize channel leave message
    static std::vector<uint8_t> serializeChannelLeaveMessage(const BitchatChannelLeaveMessage &message);

    /// Deserialize channel leave message
    static std::shared_ptr<BitchatChannelLeaveMessage> deserializeChannelLeaveMessage(const std::vector<uint8_t> &data);

    /// Serialize peer info message
    static std::vector<uint8_t> serializePeerInfoMessage(const BitchatPeerInfoMessage &message);

    /// Deserialize peer info message
    static std::shared_ptr<BitchatPeerInfoMessage> deserializePeerInfoMessage(const std::vector<uint8_t> &data);

    /// Serialize channel key share message
    static std::vector<uint8_t> serializeChannelKeyShareMessage(const BitchatChannelKeyShareMessage &message);

    /// Deserialize channel key share message
    static std::shared_ptr<BitchatChannelKeyShareMessage> deserializeChannelKeyShareMessage(const std::vector<uint8_t> &data);

    /// Serialize keep alive message
    static std::vector<uint8_t> serializeKeepAliveMessage(const BitchatKeepAliveMessage &message);

    /// Deserialize keep alive message
    static std::shared_ptr<BitchatKeepAliveMessage> deserializeKeepAliveMessage(const std::vector<uint8_t> &data);

    /// Serialize error message
    static std::vector<uint8_t> serializeErrorMessage(const BitchatErrorMessage &message);

    /// Deserialize error message
    static std::shared_ptr<BitchatErrorMessage> deserializeErrorMessage(const std::vector<uint8_t> &data);

    // Validation

    /// Validate binary packet
    static bool validatePacket(const std::vector<uint8_t> &data);

    /// Validate packet header
    static bool validateHeader(const BinaryPacketHeader &header);

    /// Validate payload size
    static bool validatePayloadSize(size_t payloadSize);

    /// Validate checksum
    static bool validateChecksum(const BinaryPacketHeader &header, const std::vector<uint8_t> &payload);

    // Utility

    /// Get message type from binary data
    static BitchatMessageType getMessageType(const std::vector<uint8_t> &data);

    /// Get payload from binary data
    static std::vector<uint8_t> getPayload(const std::vector<uint8_t> &data);

    /// Create error packet
    static std::vector<uint8_t> createErrorPacket(BitchatErrorCode errorCode, const std::string &errorMessage);

private:
    // Internal Serialization Helpers

    static std::vector<uint8_t> serializeString(const std::string &str);
    static std::string deserializeString(const std::vector<uint8_t> &data, size_t &offset);

    static std::vector<uint8_t> serializeTimestamp(const std::chrono::system_clock::time_point &timestamp);
    static std::chrono::system_clock::time_point deserializeTimestamp(const std::vector<uint8_t> &data, size_t &offset);

    static std::vector<uint8_t> serializeBytes(const std::vector<uint8_t> &bytes);
    static std::vector<uint8_t> deserializeBytes(const std::vector<uint8_t> &data, size_t &offset);

    static std::vector<uint8_t> serializeUint16(uint16_t value);
    static uint16_t deserializeUint16(const std::vector<uint8_t> &data, size_t &offset);

    static std::vector<uint8_t> serializeUint8(uint8_t value);
    static uint8_t deserializeUint8(const std::vector<uint8_t> &data, size_t &offset);

    static std::vector<uint8_t> serializeInt32(int32_t value);
    static int32_t deserializeInt32(const std::vector<uint8_t> &data, size_t &offset);

    static std::vector<uint8_t> serializeBool(bool value);
    static bool deserializeBool(const std::vector<uint8_t> &data, size_t &offset);

    // Checksum

    static uint16_t computeChecksum(const std::vector<uint8_t> &data);
    static uint16_t computeFletcher16(const std::vector<uint8_t> &data);
};

// Binary Protocol Parser

class BinaryProtocolParser
{
public:
    BinaryProtocolParser();

    /// Parse binary data into messages
    std::vector<std::shared_ptr<BitchatMessage>> parseData(const std::vector<uint8_t> &data);

    /// Get remaining incomplete data
    std::vector<uint8_t> getRemainingData() const;

    /// Clear parser state
    void clear();

    /// Check if parser has incomplete data
    bool hasIncompleteData() const;

private:
    std::vector<uint8_t> buffer_;

    std::shared_ptr<BitchatMessage> parseNextMessage();
    bool hasCompleteMessage() const;
    size_t getNextMessageSize() const;
};

// Binary Protocol Builder

class BinaryProtocolBuilder
{
public:
    BinaryProtocolBuilder();

    /// Build a complete packet
    std::vector<uint8_t> buildPacket(const BitchatMessage &message);

    /// Build packet header
    BinaryPacketHeader buildHeader(BitchatMessageType messageType, size_t payloadSize);

    /// Build payload for message type
    std::vector<uint8_t> buildPayload(const BitchatMessage &message);

    /// Finalize packet with checksum
    std::vector<uint8_t> finalizePacket(const BinaryPacketHeader &header, const std::vector<uint8_t> &payload);

private:
    std::vector<uint8_t> buildBasePayload(const BitchatMessage &message);
};

} // namespace protocol
} // namespace bitchat
