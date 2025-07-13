#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bitchat
{

// Packet type constants
constexpr uint8_t PKT_VERSION = 1;
constexpr uint8_t PKT_TYPE_ANNOUNCE = 0x01;
constexpr uint8_t PKT_TYPE_KEYEXCHANGE = 0x02;
constexpr uint8_t PKT_TYPE_LEAVE = 0x03;
constexpr uint8_t PKT_TYPE_MESSAGE = 0x04;
constexpr uint8_t PKT_TYPE_FRAGMENT_START = 0x05;
constexpr uint8_t PKT_TYPE_FRAGMENT_CONTINUE = 0x06;
constexpr uint8_t PKT_TYPE_FRAGMENT_END = 0x07;
constexpr uint8_t PKT_TYPE_CHANNEL_ANNOUNCE = 0x08;
constexpr uint8_t PKT_TYPE_CHANNEL_RETENTION = 0x09;
constexpr uint8_t PKT_TYPE_DELIVERY_ACK = 0x0A;
constexpr uint8_t PKT_TYPE_DELIVERY_STATUS_REQUEST = 0x0B;
constexpr uint8_t PKT_TYPE_READ_RECEIPT = 0x0C;

// Packet flags
constexpr uint8_t FLAG_HAS_RECIPIENT = 0x01;
constexpr uint8_t FLAG_HAS_SIGNATURE = 0x02;
constexpr uint8_t FLAG_IS_COMPRESSED = 0x04;

// Default TTL
constexpr uint8_t PKT_TTL = 7;

// BitchatPacket: represents a protocol packet sent via Bluetooth
struct BitchatPacket
{
    uint8_t version = PKT_VERSION;
    uint8_t type = 0;
    uint8_t ttl = PKT_TTL;
    uint64_t timestamp = 0;
    uint8_t flags = 0;
    uint16_t payloadLength = 0;
    std::vector<uint8_t> senderID;
    std::vector<uint8_t> recipientID;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> signature;

    BitchatPacket() = default;
};

// BitchatMessage: represents a chat message
struct BitchatMessage
{
    std::string id;
    std::string sender;
    std::string content;
    uint64_t timestamp = 0;
    bool isRelay = false;
    std::string originalSender;
    bool isPrivate = false;
    std::string recipientNickname;
    std::vector<uint8_t> senderPeerID;
    std::vector<std::string> mentions;
    std::string channel;
    std::vector<uint8_t> encryptedContent;
    bool isEncrypted = false;

    BitchatMessage() = default;
};

// OnlinePeer: represents an online peer in the network
struct OnlinePeer
{
    std::string nick;
    std::string canal;
    std::vector<uint8_t> peerid;
    time_t lastSeen = 0;
    int rssi = -100;
    bool hasAnnounced = false;
    std::string peripheralUUID;

    OnlinePeer() = default;
};

// Utility functions
std::string packetTypeToString(uint8_t type);
std::string toHex(const std::vector<uint8_t> &data);
std::string toHexCompact(const std::vector<uint8_t> &data);
std::vector<uint8_t> stringToVector(const std::string &str);
std::string vectorToString(const std::vector<uint8_t> &vec);
std::string normalizePeerId(const std::string &peerId);
std::string randomPeerId();
std::string uuidv4();
std::string randomNickname();

} // namespace bitchat