#include "bitchat/protocol/packet_serializer.h"
#include "bitchat/compression/compression_manager.h"
#include "bitchat/crypto/crypto_manager.h"
#include <algorithm>
#include <iostream>

namespace bitchat
{

PacketSerializer::PacketSerializer() = default;

std::vector<uint8_t> PacketSerializer::serializePacket(const BitchatPacket &packet)
{
    std::vector<uint8_t> data;

    // Try to compress payload if beneficial
    std::vector<uint8_t> payload = packet.payload;
    uint16_t originalPayloadSize = 0;
    bool isCompressed = false;

    CompressionManager compressionManager;
    if (compressionManager.shouldCompress(packet.payload))
    {
        std::vector<uint8_t> compressedPayload = compressionManager.compressData(packet.payload);
        if (compressedPayload.size() < packet.payload.size())
        {
            originalPayloadSize = packet.payload.size();
            payload = compressedPayload;
            isCompressed = true;
        }
    }

    // Header (13 bytes)
    writeUint8(data, packet.version);
    writeUint8(data, packet.type);
    writeUint8(data, packet.ttl);
    writeUint64(data, packet.timestamp);

    // Flags (include compression flag if needed)
    uint8_t flags = packet.flags;
    if (isCompressed)
    {
        flags |= FLAG_IS_COMPRESSED;
    }
    writeUint8(data, flags);

    // Payload length (2 bytes, big-endian) - includes original size if compressed
    uint16_t payloadDataSize = static_cast<uint16_t>(payload.size() + (isCompressed ? 2 : 0));
    writeUint16(data, payloadDataSize);

    // SenderID (8 bytes, pad with zeros if needed)
    std::vector<uint8_t> senderID = packet.senderID;
    senderID.resize(8, 0);
    data.insert(data.end(), senderID.begin(), senderID.end());

    // RecipientID (8 bytes, if present)
    if (packet.flags & FLAG_HAS_RECIPIENT)
    {
        std::vector<uint8_t> recipientID = packet.recipientID;
        recipientID.resize(8, 0);
        data.insert(data.end(), recipientID.begin(), recipientID.end());
    }

    // Payload (with original size prepended if compressed)
    if (isCompressed)
    {
        // Prepend original size (2 bytes, big-endian)
        writeUint16(data, originalPayloadSize);
    }
    data.insert(data.end(), payload.begin(), payload.end());

    // Signature (64 bytes, if present)
    if (packet.flags & FLAG_HAS_SIGNATURE)
    {
        std::vector<uint8_t> signature = packet.signature;
        signature.resize(64, 0);
        data.insert(data.end(), signature.begin(), signature.end());
    }

    return data;
}

BitchatPacket PacketSerializer::deserializePacket(const std::vector<uint8_t> &data)
{
    BitchatPacket packet;
    size_t offset = 0;

    // Verify minimum size: headerSize (13) + senderIDSize (8) = 21 bytes
    if (data.size() < 21)
    {
        std::cerr << "ERROR: Packet too short: " << data.size() << " bytes (minimum 21)" << std::endl;
        return packet;
    }

    // Header (13 bytes)
    packet.version = readUint8(data, offset);
    packet.type = readUint8(data, offset);
    packet.ttl = readUint8(data, offset);
    packet.timestamp = readUint64(data, offset);

    // Flags
    packet.flags = readUint8(data, offset);
    bool isCompressed = (packet.flags & FLAG_IS_COMPRESSED) != 0;

    // Payload length (2 bytes, big-endian)
    packet.payloadLength = readUint16(data, offset);

    // Calculate expected total size
    size_t expectedSize = 21; // headerSize + senderIDSize
    if (packet.flags & FLAG_HAS_RECIPIENT)
    {
        expectedSize += 8; // recipientIDSize
    }
    if (packet.flags & FLAG_HAS_SIGNATURE)
    {
        expectedSize += 64; // signatureSize
    }
    expectedSize += packet.payloadLength;

    if (!validatePacketSize(data, expectedSize))
    {
        std::cerr << "ERROR: Packet size mismatch. Expected: " << expectedSize
                  << ", got: " << data.size() << std::endl;
        return packet;
    }

    // SenderID (8 bytes)
    packet.senderID.assign(data.begin() + offset, data.begin() + offset + 8);
    offset += 8;

    // RecipientID (8 bytes, if present)
    if (packet.flags & FLAG_HAS_RECIPIENT)
    {
        packet.recipientID.assign(data.begin() + offset, data.begin() + offset + 8);
        offset += 8;
    }

    // Payload (with decompression if needed)
    if (isCompressed)
    {
        // First 2 bytes are original size
        if (packet.payloadLength < 2)
        {
            std::cerr << "ERROR: Compressed payload too small for size header" << std::endl;
            return packet;
        }

        uint16_t originalSize = readUint16(data, offset);

        // Compressed payload
        std::vector<uint8_t> compressedPayload(data.begin() + offset,
                                               data.begin() + offset + packet.payloadLength - 2);
        offset += packet.payloadLength - 2;

        // Decompress
        CompressionManager compressionManager;
        packet.payload = compressionManager.decompressData(compressedPayload, originalSize);
    }
    else
    {
        // Normal payload
        if (offset + packet.payloadLength <= data.size())
        {
            packet.payload.assign(data.begin() + offset,
                                  data.begin() + offset + packet.payloadLength);
            offset += packet.payloadLength;
        }
    }

    // Signature (64 bytes, if present)
    if ((packet.flags & FLAG_HAS_SIGNATURE) && offset + 64 <= data.size())
    {
        packet.signature.assign(data.begin() + offset, data.begin() + offset + 64);
    }

    return packet;
}

std::vector<uint8_t> PacketSerializer::makeMessagePayload(const BitchatMessage &message)
{
    std::vector<uint8_t> data;

    // Flags - calculate based on present fields
    uint8_t flags = 0;
    if (message.isRelay)
        flags |= 0x01;
    if (message.isPrivate)
        flags |= 0x02;
    if (!message.originalSender.empty())
        flags |= 0x04;
    if (!message.recipientNickname.empty())
        flags |= 0x08;
    if (!message.senderPeerID.empty())
        flags |= 0x10;
    if (!message.mentions.empty())
        flags |= 0x20;
    if (!message.channel.empty())
        flags |= 0x40;
    if (message.isEncrypted)
        flags |= 0x80;
    writeUint8(data, flags);

    // Timestamp (8 bytes, milliseconds)
    writeUint64(data, message.timestamp);

    // Message ID (variable length, max 255 bytes)
    std::string id = message.id.empty() ? uuidv4() : message.id;
    writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), id.size())));
    data.insert(data.end(), id.begin(),
                id.begin() + std::min(static_cast<size_t>(255), id.size()));

    // Sender nickname (variable length, max 255 bytes)
    writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), message.sender.size())));
    data.insert(data.end(), message.sender.begin(),
                message.sender.begin() + std::min(static_cast<size_t>(255), message.sender.size()));

    // Content length and content (2 bytes for length, max 65535)
    uint16_t contentLength = static_cast<uint16_t>(std::min(static_cast<size_t>(65535), message.content.size()));
    writeUint16(data, contentLength);
    data.insert(data.end(), message.content.begin(),
                message.content.begin() + contentLength);

    // Optional fields based on flags
    if (!message.originalSender.empty())
    {
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), message.originalSender.size())));
        data.insert(data.end(), message.originalSender.begin(),
                    message.originalSender.begin() + std::min(static_cast<size_t>(255), message.originalSender.size()));
    }

    if (!message.recipientNickname.empty())
    {
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), message.recipientNickname.size())));
        data.insert(data.end(), message.recipientNickname.begin(),
                    message.recipientNickname.begin() + std::min(static_cast<size_t>(255), message.recipientNickname.size()));
    }

    if (!message.senderPeerID.empty())
    {
        // Convert peer ID bytes to hex string for Swift compatibility
        std::string peerIDHex = toHexCompact(message.senderPeerID);
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), peerIDHex.size())));
        data.insert(data.end(), peerIDHex.begin(),
                    peerIDHex.begin() + std::min(static_cast<size_t>(255), peerIDHex.size()));
    }

    // Mentions array
    if (!message.mentions.empty())
    {
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), message.mentions.size())));
        for (const auto &mention : message.mentions)
        {
            writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), mention.size())));
            data.insert(data.end(), mention.begin(),
                        mention.begin() + std::min(static_cast<size_t>(255), mention.size()));
        }
    }

    // Channel (only if present)
    if (!message.channel.empty())
    {
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), message.channel.size())));
        data.insert(data.end(), message.channel.begin(),
                    message.channel.begin() + std::min(static_cast<size_t>(255), message.channel.size()));
    }

    return data;
}

BitchatMessage PacketSerializer::parseMessagePayload(const std::vector<uint8_t> &payload)
{
    BitchatMessage message;
    size_t offset = 0;

    // Minimum size: flags(1) + timestamp(8) + id_len(1) + sender_len(1) + content_len(2) = 13 bytes
    if (payload.size() < 13)
    {
        std::cerr << "ERROR: Payload too small: " << payload.size() << " < 13" << std::endl;
        return message;
    }

    // Flags (1 byte)
    uint8_t flags = readUint8(payload, offset);
    message.isRelay = (flags & 0x01) != 0;
    message.isPrivate = (flags & 0x02) != 0;
    bool hasOriginalSender = (flags & 0x04) != 0;
    bool hasRecipientNickname = (flags & 0x08) != 0;
    bool hasSenderPeerID = (flags & 0x10) != 0;
    bool hasMentions = (flags & 0x20) != 0;
    bool hasChannel = (flags & 0x40) != 0;
    message.isEncrypted = (flags & 0x80) != 0;

    // Timestamp (8 bytes, milliseconds) - big-endian
    message.timestamp = readUint64(payload, offset);

    // Message ID length (1 byte)
    auto idLen = readUint8(payload, offset);

    // Message ID (variable length)
    if (offset + idLen > payload.size())
    {
        std::cerr << "ERROR: Buffer overflow reading ID data" << std::endl;
        return message;
    }
    message.id = std::string(payload.begin() + offset, payload.begin() + offset + idLen);
    offset += idLen;

    // Sender length (1 byte)
    auto senderLen = readUint8(payload, offset);

    // Sender (variable length)
    if (offset + senderLen > payload.size())
    {
        std::cerr << "ERROR: Buffer overflow reading sender data" << std::endl;
        return message;
    }
    message.sender = std::string(payload.begin() + offset, payload.begin() + offset + senderLen);
    offset += senderLen;

    // Content length (2 bytes, big-endian)
    uint16_t contentLen = readUint16(payload, offset);

    // Content (variable length)
    if (offset + contentLen > payload.size())
    {
        std::cerr << "ERROR: Buffer overflow reading content data" << std::endl;
        return message;
    }

    if (message.isEncrypted)
    {
        // Store encrypted content as bytes
        message.encryptedContent.assign(payload.begin() + offset, payload.begin() + offset + contentLen);
        message.content = ""; // Empty placeholder
    }
    else
    {
        // Normal string content
        message.content = std::string(payload.begin() + offset, payload.begin() + offset + contentLen);
    }
    offset += contentLen;

    // Optional fields based on flags
    if (hasOriginalSender && offset < payload.size())
    {
        auto len = readUint8(payload, offset);
        if (offset + len <= payload.size())
        {
            message.originalSender = std::string(payload.begin() + offset, payload.begin() + offset + len);
            offset += len;
        }
    }

    if (hasRecipientNickname && offset < payload.size())
    {
        auto len = readUint8(payload, offset);
        if (offset + len <= payload.size())
        {
            message.recipientNickname = std::string(payload.begin() + offset, payload.begin() + offset + len);
            offset += len;
        }
    }

    if (hasSenderPeerID && offset < payload.size())
    {
        auto len = readUint8(payload, offset);
        if (offset + len <= payload.size())
        {
            std::string peerIDHex = std::string(payload.begin() + offset, payload.begin() + offset + len);
            // Convert hex string back to bytes
            message.senderPeerID.clear();
            for (size_t i = 0; i < len; i += 2)
            {
                if (i + 1 < len)
                {
                    std::string byteStr = peerIDHex.substr(i, 2);
                    try
                    {
                        message.senderPeerID.push_back(static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16)));
                    }
                    catch (const std::exception &e)
                    {
                        // Skip invalid hex bytes
                        continue;
                    }
                }
            }
            offset += len;
        }
    }

    // Mentions array
    if (hasMentions && offset < payload.size())
    {
        auto mentionCount = readUint8(payload, offset);
        for (uint8_t i = 0; i < mentionCount && offset < payload.size(); ++i)
        {
            auto len = readUint8(payload, offset);
            if (offset + len <= payload.size())
            {
                message.mentions.push_back(std::string(payload.begin() + offset, payload.begin() + offset + len));
                offset += len;
            }
        }
    }

    // Channel
    if (hasChannel && offset < payload.size())
    {
        auto len = readUint8(payload, offset);
        if (offset + len <= payload.size())
        {
            message.channel = std::string(payload.begin() + offset, payload.begin() + offset + len);
        }
    }

    return message;
}

std::vector<uint8_t> PacketSerializer::makeAnnouncePayload(const std::string &nickname)
{
    return std::vector<uint8_t>(nickname.begin(), nickname.end());
}

void PacketSerializer::parseAnnouncePayload(const std::vector<uint8_t> &payload, std::string &nickname)
{
    nickname = std::string(payload.begin(), payload.end());
}

BitchatPacket PacketSerializer::makePacket(uint8_t type, const std::vector<uint8_t> &payload,
                                           bool hasRecipient, bool hasSignature, const std::string &senderId)
{
    BitchatPacket packet;
    packet.type = type;
    packet.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();

    // Convert string to UTF-8 bytes for Swift compatibility
    std::vector<uint8_t> senderID(senderId.begin(), senderId.end());
    senderID.resize(8, 0); // Pad to 8 bytes
    packet.senderID = senderID;
    packet.payload = payload;
    packet.payloadLength = payload.size();
    packet.ttl = 6; // Use TTL 6 as in Swift

    // Flags
    packet.flags = 0;
    if (hasRecipient)
        packet.flags |= FLAG_HAS_RECIPIENT;
    if (hasSignature)
        packet.flags |= FLAG_HAS_SIGNATURE;

    // Recipient ID (broadcast = all 0xFF for Swift compatibility)
    if (hasRecipient)
    {
        packet.recipientID = std::vector<uint8_t>(8, 0xFF); // Broadcast to all
    }

    return packet;
}

// Helper functions for serialization
void PacketSerializer::writeUint64(std::vector<uint8_t> &data, uint64_t value)
{
    for (int i = 7; i >= 0; --i)
    {
        data.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

void PacketSerializer::writeUint16(std::vector<uint8_t> &data, uint16_t value)
{
    data.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(value & 0xFF));
}

void PacketSerializer::writeUint8(std::vector<uint8_t> &data, uint8_t value)
{
    data.push_back(value);
}

// Helper functions for deserialization
uint64_t PacketSerializer::readUint64(const std::vector<uint8_t> &data, size_t &offset)
{
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i)
    {
        value = (value << 8) | data[offset++];
    }
    return value;
}

uint16_t PacketSerializer::readUint16(const std::vector<uint8_t> &data, size_t &offset)
{
    uint16_t value = static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
    offset += 2;
    return value;
}

uint8_t PacketSerializer::readUint8(const std::vector<uint8_t> &data, size_t &offset)
{
    return data[offset++];
}

bool PacketSerializer::validatePacketSize(const std::vector<uint8_t> &data, size_t expectedSize)
{
    return data.size() >= expectedSize;
}

} // namespace bitchat