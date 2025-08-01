#include "bitchat/protocol/packet_serializer.h"
#include "bitchat/helpers/compression_helper.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/protocol/message_padding.h"
#include "bitchat/services/crypto_service.h"
#include <algorithm>
#include <spdlog/spdlog.h>

namespace bitchat
{

PacketSerializer::PacketSerializer() = default;

std::vector<uint8_t> PacketSerializer::serializePacket(const BitchatPacket &packet)
{
    std::vector<uint8_t> data;

    // Compress payload if beneficial
    std::vector<uint8_t> payload = packet.getPayload();
    uint16_t originalPayloadSize = 0;
    bool isCompressed = false;

    if (CompressionHelper::shouldCompress(packet.getPayload()))
    {
        std::vector<uint8_t> compressedPayload = CompressionHelper::compressData(packet.getPayload());

        if (compressedPayload.size() < packet.getPayload().size())
        {
            originalPayloadSize = packet.getPayload().size();
            payload = compressedPayload;
            isCompressed = true;
        }
    }

    // Header (13 bytes)
    writeUint8(data, packet.getVersion());
    writeUint8(data, packet.getType());
    writeUint8(data, packet.getTTL());
    writeUint64(data, packet.getTimestamp());

    // Flags (include compression flag if needed)
    uint8_t flags = packet.getFlags();

    if (isCompressed)
    {
        flags |= FLAG_IS_COMPRESSED;
    }

    writeUint8(data, flags);

    // Payload length (2 bytes, big-endian) - includes original size if compressed
    uint16_t payloadDataSize = static_cast<uint16_t>(payload.size() + (isCompressed ? 2 : 0));
    writeUint16(data, payloadDataSize);

    // SenderID (8 bytes, pad with zeros if needed)
    std::vector<uint8_t> senderID = packet.getSenderID();
    senderID.resize(8, 0);
    data.insert(data.end(), senderID.begin(), senderID.end());

    // RecipientID (8 bytes, if present)
    if (packet.getFlags() & FLAG_HAS_RECIPIENT)
    {
        std::vector<uint8_t> recipientID = packet.getRecipientID();
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
    if (packet.getFlags() & FLAG_HAS_SIGNATURE)
    {
        std::vector<uint8_t> signature = packet.getSignature();
        signature.resize(64, 0);
        data.insert(data.end(), signature.begin(), signature.end());
    }

    // Apply padding to standard block sizes for traffic analysis resistance
    size_t optimalSize = MessagePadding::optimalBlockSize(data.size());
    std::vector<uint8_t> paddedData = MessagePadding::pad(data, optimalSize);

    return paddedData;
}

BitchatPacket PacketSerializer::deserializePacket(const std::vector<uint8_t> &data)
{
    BitchatPacket packet;
    size_t offset = 0;

    // Remove padding first
    std::vector<uint8_t> unpaddedData = MessagePadding::unpad(data);

    // Verify minimum size: headerSize (13) + senderIDSize (8) = 21 bytes
    if (unpaddedData.size() < 21)
    {
        spdlog::error("Packet too short: {} bytes (minimum 21)", unpaddedData.size());
        return packet;
    }

    // Header (13 bytes)
    packet.setVersion(readUint8(unpaddedData, offset));
    packet.setType(readUint8(unpaddedData, offset));
    packet.setTTL(readUint8(unpaddedData, offset));
    packet.setTimestamp(readUint64(unpaddedData, offset));

    // Flags
    packet.setFlags(readUint8(unpaddedData, offset));
    bool isCompressed = (packet.getFlags() & FLAG_IS_COMPRESSED) != 0;

    // Payload length (2 bytes, big-endian)
    packet.setPayloadLength(readUint16(unpaddedData, offset));

    // Calculate expected total size
    size_t expectedSize = 21; // headerSize + senderIDSize
    if (packet.getFlags() & FLAG_HAS_RECIPIENT)
    {
        expectedSize += 8; // recipientIDSize
    }

    if (packet.getFlags() & FLAG_HAS_SIGNATURE)
    {
        expectedSize += 64; // signatureSize
    }

    expectedSize += packet.getPayloadLength();

    if (!validatePacketSize(unpaddedData, expectedSize))
    {
        spdlog::error("Packet size mismatch. Expected: {}, got: {}", expectedSize, unpaddedData.size());
        return packet;
    }

    // SenderID (8 bytes)
    std::vector<uint8_t> senderID(unpaddedData.begin() + offset, unpaddedData.begin() + offset + 8);
    packet.setSenderID(senderID);
    offset += 8;

    // RecipientID (8 bytes, if present)
    if (packet.getFlags() & FLAG_HAS_RECIPIENT)
    {
        std::vector<uint8_t> recipientID(unpaddedData.begin() + offset, unpaddedData.begin() + offset + 8);
        packet.setRecipientID(recipientID);
        offset += 8;
    }

    // Payload (with decompression if needed)
    if (isCompressed)
    {
        // First 2 bytes are original size
        if (packet.getPayloadLength() < 2)
        {
            spdlog::error("Compressed payload too small for size header");
            return packet;
        }

        uint16_t originalSize = readUint16(unpaddedData, offset);

        // Compressed payload
        std::vector<uint8_t> compressedPayload(unpaddedData.begin() + offset, unpaddedData.begin() + offset + packet.getPayloadLength() - 2);
        offset += packet.getPayloadLength() - 2;

        // Decompress
        std::vector<uint8_t> payload = CompressionHelper::decompressData(compressedPayload, originalSize);
        packet.setPayload(payload);
    }
    else
    {
        // Normal payload
        if (offset + packet.getPayloadLength() <= unpaddedData.size())
        {
            std::vector<uint8_t> payload(unpaddedData.begin() + offset, unpaddedData.begin() + offset + packet.getPayloadLength());
            packet.setPayload(payload);
            offset += packet.getPayloadLength();
        }
    }

    // Signature (64 bytes, if present)
    if ((packet.getFlags() & FLAG_HAS_SIGNATURE) && offset + 64 <= unpaddedData.size())
    {
        std::vector<uint8_t> signature(unpaddedData.begin() + offset, unpaddedData.begin() + offset + 64);
        packet.setSignature(signature);
    }

    return packet;
}

std::vector<uint8_t> PacketSerializer::makeMessagePayload(const BitchatMessage &message)
{
    std::vector<uint8_t> data;

    // Calculate flags based on present fields
    uint8_t flags = 0;

    if (message.isRelay())
    {
        flags |= 0x01;
    }

    if (message.isPrivate())
    {
        flags |= 0x02;
    }

    if (!message.getOriginalSender().empty())
    {
        flags |= 0x04;
    }

    if (!message.getRecipientNickname().empty())
    {
        flags |= 0x08;
    }

    if (!message.getSenderPeerID().empty())
    {
        flags |= 0x10;
    }

    if (!message.getMentions().empty())
    {
        flags |= 0x20;
    }

    if (!message.getChannel().empty())
    {
        flags |= 0x40;
    }

    if (message.isEncrypted())
    {
        flags |= 0x80;
    }

    writeUint8(data, flags);

    // Timestamp (8 bytes, milliseconds)
    writeUint64(data, message.getTimestamp());

    // Message ID (variable length, max 255 bytes)
    std::string id = message.getId().empty() ? StringHelper::createUUID() : message.getId();
    writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), id.size())));
    data.insert(data.end(), id.begin(), id.begin() + std::min(static_cast<size_t>(255), id.size()));

    // Sender nickname (variable length, max 255 bytes)
    writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), message.getSender().size())));
    data.insert(data.end(), message.getSender().begin(), message.getSender().begin() + std::min(static_cast<size_t>(255), message.getSender().size()));

    // Content length and content (2 bytes for length, max 65535)
    uint16_t contentLength = static_cast<uint16_t>(std::min(static_cast<size_t>(65535), message.getContent().size()));
    writeUint16(data, contentLength);
    data.insert(data.end(), message.getContent().begin(), message.getContent().begin() + contentLength);

    // Optional fields based on flags
    if (!message.getOriginalSender().empty())
    {
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), message.getOriginalSender().size())));
        data.insert(data.end(), message.getOriginalSender().begin(), message.getOriginalSender().begin() + std::min(static_cast<size_t>(255), message.getOriginalSender().size()));
    }

    if (!message.getRecipientNickname().empty())
    {
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), message.getRecipientNickname().size())));
        data.insert(data.end(), message.getRecipientNickname().begin(), message.getRecipientNickname().begin() + std::min(static_cast<size_t>(255), message.getRecipientNickname().size()));
    }

    if (!message.getSenderPeerID().empty())
    {
        // Convert peer ID bytes to hex string for Swift compatibility
        std::string peerIDHex = StringHelper::toHex(message.getSenderPeerID());
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), peerIDHex.size())));
        data.insert(data.end(), peerIDHex.begin(), peerIDHex.begin() + std::min(static_cast<size_t>(255), peerIDHex.size()));
    }

    // Mentions array
    if (!message.getMentions().empty())
    {
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), message.getMentions().size())));

        for (const auto &mention : message.getMentions())
        {
            writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), mention.size())));
            data.insert(data.end(), mention.begin(), mention.begin() + std::min(static_cast<size_t>(255), mention.size()));
        }
    }

    // Channel (only if present)
    if (!message.getChannel().empty())
    {
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), message.getChannel().size())));
        data.insert(data.end(), message.getChannel().begin(), message.getChannel().begin() + std::min(static_cast<size_t>(255), message.getChannel().size()));
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
        spdlog::error("Payload too small: {} < 13", payload.size());
        return message;
    }

    // Flags (1 byte)
    uint8_t flags = readUint8(payload, offset);
    message.setRelay((flags & 0x01) != 0);
    message.setPrivate((flags & 0x02) != 0);
    bool hasOriginalSender = (flags & 0x04) != 0;
    bool hasRecipientNickname = (flags & 0x08) != 0;
    bool hasSenderPeerID = (flags & 0x10) != 0;
    bool hasMentions = (flags & 0x20) != 0;
    bool hasChannel = (flags & 0x40) != 0;
    message.setEncrypted((flags & 0x80) != 0);

    // Timestamp (8 bytes, milliseconds) - big-endian
    message.setTimestamp(readUint64(payload, offset));

    // Message ID length (1 byte)
    auto idLen = readUint8(payload, offset);

    // Message ID (variable length)
    if (offset + idLen > payload.size())
    {
        spdlog::error("Buffer overflow reading ID data");
        return message;
    }

    message.setId(std::string(payload.begin() + offset, payload.begin() + offset + idLen));
    offset += idLen;

    // Sender length (1 byte)
    auto senderLen = readUint8(payload, offset);

    // Sender (variable length)
    if (offset + senderLen > payload.size())
    {
        spdlog::error("Buffer overflow reading sender data");
        return message;
    }

    message.setSender(std::string(payload.begin() + offset, payload.begin() + offset + senderLen));
    offset += senderLen;

    // Content length (2 bytes, big-endian)
    uint16_t contentLen = readUint16(payload, offset);

    // Content (variable length)
    if (offset + contentLen > payload.size())
    {
        spdlog::error("Buffer overflow reading content data");
        return message;
    }

    if (message.isEncrypted())
    {
        // Store encrypted content as bytes
        std::vector<uint8_t> encryptedContent(payload.begin() + offset, payload.begin() + offset + contentLen);
        message.setEncryptedContent(encryptedContent);

        // Empty placeholder
        message.setContent("");
    }
    else
    {
        // Normal string content
        message.setContent(std::string(payload.begin() + offset, payload.begin() + offset + contentLen));
    }

    offset += contentLen;

    // Optional fields based on flags
    if (hasOriginalSender && offset < payload.size())
    {
        auto len = readUint8(payload, offset);
        if (offset + len <= payload.size())
        {
            message.setOriginalSender(std::string(payload.begin() + offset, payload.begin() + offset + len));
            offset += len;
        }
    }

    if (hasRecipientNickname && offset < payload.size())
    {
        auto len = readUint8(payload, offset);
        if (offset + len <= payload.size())
        {
            message.setRecipientNickname(std::string(payload.begin() + offset, payload.begin() + offset + len));
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
            std::vector<uint8_t> senderPeerID;

            for (size_t i = 0; i < len; i += 2)
            {
                if (i + 1 < len)
                {
                    std::string byteStr = peerIDHex.substr(i, 2);

                    try
                    {
                        senderPeerID.push_back(static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16)));
                    }
                    catch (const std::exception &e)
                    {
                        // Skip invalid hex bytes
                        continue;
                    }
                }
            }

            message.setSenderPeerID(senderPeerID);

            offset += len;
        }
    }

    // Mentions array
    if (hasMentions && offset < payload.size())
    {
        auto mentionCount = readUint8(payload, offset);
        std::vector<std::string> mentions;

        for (uint8_t i = 0; i < mentionCount && offset < payload.size(); ++i)
        {
            auto len = readUint8(payload, offset);
            if (offset + len <= payload.size())
            {
                mentions.push_back(std::string(payload.begin() + offset, payload.begin() + offset + len));
                offset += len;
            }
        }

        message.setMentions(mentions);
    }

    // Channel
    if (hasChannel && offset < payload.size())
    {
        auto len = readUint8(payload, offset);
        if (offset + len <= payload.size())
        {
            message.setChannel(std::string(payload.begin() + offset, payload.begin() + offset + len));
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

BitchatPacket PacketSerializer::makePacket(uint8_t type, const std::vector<uint8_t> &payload, bool hasRecipient, bool hasSignature, const std::string &senderID)
{
    BitchatPacket packet;
    packet.setType(type);
    packet.setTimestamp(DateTimeHelper::getCurrentTimestamp());

    // Convert string to UTF-8 bytes
    std::vector<uint8_t> currentSenderID(senderID.begin(), senderID.end());
    currentSenderID.resize(8, 0); // Pad to 8 bytes
    packet.setSenderID(currentSenderID);
    packet.setPayload(payload);
    packet.setTTL(6);

    // Flags
    uint8_t flags = 0;
    if (hasRecipient)
    {
        flags |= FLAG_HAS_RECIPIENT;
    }

    if (hasSignature)
    {
        flags |= FLAG_HAS_SIGNATURE;
    }

    packet.setFlags(flags);

    // Recipient ID (broadcast = all 0xFF)
    if (hasRecipient)
    {
        // Broadcast to all
        packet.setRecipientID(std::vector<uint8_t>(8, 0xFF));
    }

    return packet;
}

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

std::vector<uint8_t> PacketSerializer::makeChannelAnnouncePayload(const std::string &channel, bool joining)
{
    std::vector<uint8_t> data;

    // Join flag (1 byte)
    writeUint8(data, joining ? 1 : 0);

    // Channel length (1 byte)
    writeUint8(data, static_cast<uint8_t>(channel.length()));

    // Channel name
    data.insert(data.end(), channel.begin(), channel.end());

    return data;
}

void PacketSerializer::parseChannelAnnouncePayload(const std::vector<uint8_t> &payload, std::string &channel, bool &joining)
{
    if (payload.size() < 2)
    {
        spdlog::error("Channel announce payload too short");
        return;
    }

    size_t offset = 0;

    // Join flag (1 byte)
    joining = readUint8(payload, offset) != 0;

    // Channel length (1 byte)
    uint8_t channelLen = readUint8(payload, offset);

    // Channel name
    if (offset + channelLen <= payload.size())
    {
        channel = std::string(payload.begin() + offset, payload.begin() + offset + channelLen);
    }
    else
    {
        spdlog::error("Channel announce payload buffer overflow");
    }
}

std::vector<uint8_t> PacketSerializer::makeVersionHelloPayload(const std::vector<uint8_t> &supportedVersions, uint8_t preferredVersion, const std::string &clientVersion, const std::string &platform, const std::vector<std::string> &capabilities)
{
    std::vector<uint8_t> data;

    // Flags byte: bit 0 = hasCapabilities
    uint8_t flags = 0;
    if (!capabilities.empty())
    {
        flags |= 0x01;
    }
    writeUint8(data, flags);

    // Supported versions array
    writeUint8(data, static_cast<uint8_t>(supportedVersions.size()));
    for (uint8_t version : supportedVersions)
    {
        writeUint8(data, version);
    }

    // Preferred version
    writeUint8(data, preferredVersion);

    // Client version (string with length prefix)
    writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), clientVersion.length())));
    data.insert(data.end(), clientVersion.begin(), clientVersion.begin() + std::min(static_cast<size_t>(255), clientVersion.length()));

    // Platform (string with length prefix)
    writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), platform.length())));
    data.insert(data.end(), platform.begin(), platform.begin() + std::min(static_cast<size_t>(255), platform.length()));

    // Capabilities (if present)
    if (!capabilities.empty())
    {
        writeUint8(data, static_cast<uint8_t>(capabilities.size()));
        for (const std::string &capability : capabilities)
        {
            writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), capability.length())));
            data.insert(data.end(), capability.begin(), capability.begin() + std::min(static_cast<size_t>(255), capability.length()));
        }
    }

    return data;
}

void PacketSerializer::parseVersionHelloPayload(const std::vector<uint8_t> &payload, std::vector<uint8_t> &supportedVersions, uint8_t &preferredVersion, std::string &clientVersion, std::string &platform, std::vector<std::string> &capabilities)
{
    // Minimum size check: flags(1) + versionCount(1) + at least one version(1) + preferredVersion(1) + min strings
    if (payload.size() < 4)
    {
        spdlog::error("Version hello payload too short");
        return;
    }

    size_t offset = 0;

    // Flags byte
    uint8_t flags = readUint8(payload, offset);
    bool hasCapabilities = (flags & 0x01) != 0;

    // Supported versions count
    uint8_t versionCount = readUint8(payload, offset);
    supportedVersions.clear();

    for (uint8_t i = 0; i < versionCount; i++)
    {
        if (offset >= payload.size())
        {
            spdlog::error("Version hello payload buffer overflow reading supported versions");
            return;
        }

        supportedVersions.push_back(readUint8(payload, offset));
    }

    // Preferred version
    if (offset >= payload.size())
    {
        spdlog::error("Version hello payload buffer overflow reading preferred version");
        return;
    }

    preferredVersion = readUint8(payload, offset);

    // Client version (string with length prefix)
    if (offset >= payload.size())
    {
        spdlog::error("Version hello payload buffer overflow reading client version length");
        return;
    }

    uint8_t clientVersionLen = readUint8(payload, offset);

    if (offset + clientVersionLen > payload.size())
    {
        spdlog::error("Version hello payload buffer overflow reading client version");
        return;
    }

    clientVersion = std::string(payload.begin() + offset, payload.begin() + offset + clientVersionLen);
    offset += clientVersionLen;

    // Platform (string with length prefix)
    if (offset >= payload.size())
    {
        spdlog::error("Version hello payload buffer overflow reading platform length");
        return;
    }

    uint8_t platformLen = readUint8(payload, offset);

    if (offset + platformLen > payload.size())
    {
        spdlog::error("Version hello payload buffer overflow reading platform");
        return;
    }

    platform = std::string(payload.begin() + offset, payload.begin() + offset + platformLen);
    offset += platformLen;

    // Capabilities (if present)
    capabilities.clear();

    if (hasCapabilities)
    {
        if (offset >= payload.size())
        {
            spdlog::error("Version hello payload buffer overflow reading capabilities count");
            return;
        }

        uint8_t capCount = readUint8(payload, offset);

        for (uint8_t i = 0; i < capCount; i++)
        {
            if (offset >= payload.size())
            {
                spdlog::error("Version hello payload buffer overflow reading capability length");
                return;
            }

            uint8_t capLen = readUint8(payload, offset);

            if (offset + capLen > payload.size())
            {
                spdlog::error("Version hello payload buffer overflow reading capability");
                return;
            }

            capabilities.push_back(std::string(payload.begin() + offset, payload.begin() + offset + capLen));

            offset += capLen;
        }
    }
}

std::vector<uint8_t> PacketSerializer::makeVersionAckPayload(uint8_t agreedVersion, const std::string &serverVersion, const std::string &platform, bool rejected, const std::string &reason)
{
    std::vector<uint8_t> data;

    // Flags byte: bit 0 = rejected, bit 1 = hasReason
    uint8_t flags = 0;
    if (rejected)
    {
        flags |= 0x01;
    }
    if (!reason.empty())
    {
        flags |= 0x02;
    }
    writeUint8(data, flags);

    // Agreed version
    writeUint8(data, agreedVersion);

    // Server version (string with length prefix)
    writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), serverVersion.length())));
    data.insert(data.end(), serverVersion.begin(), serverVersion.begin() + std::min(static_cast<size_t>(255), serverVersion.length()));

    // Platform (string with length prefix)
    writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), platform.length())));
    data.insert(data.end(), platform.begin(), platform.begin() + std::min(static_cast<size_t>(255), platform.length()));

    // Reason (if present)
    if (!reason.empty())
    {
        writeUint8(data, static_cast<uint8_t>(std::min(static_cast<size_t>(255), reason.length())));
        data.insert(data.end(), reason.begin(), reason.begin() + std::min(static_cast<size_t>(255), reason.length()));
    }

    return data;
}

void PacketSerializer::parseVersionAckPayload(const std::vector<uint8_t> &payload, uint8_t &agreedVersion, std::string &serverVersion, std::string &platform, bool &rejected, std::string &reason)
{
    // Minimum size check: flags(1) + agreedVersion(1) + min strings
    if (payload.size() < 3)
    {
        spdlog::error("Version ack payload too short");
        return;
    }

    size_t offset = 0;

    // Flags byte
    uint8_t flags = readUint8(payload, offset);
    rejected = (flags & 0x01) != 0;
    bool hasReason = (flags & 0x02) != 0;

    // Agreed version
    if (offset >= payload.size())
    {
        spdlog::error("Version ack payload buffer overflow reading agreed version");
        return;
    }
    agreedVersion = readUint8(payload, offset);

    // Server version (string with length prefix)
    if (offset >= payload.size())
    {
        spdlog::error("Version ack payload buffer overflow reading server version length");
        return;
    }
    uint8_t serverVersionLen = readUint8(payload, offset);

    if (offset + serverVersionLen > payload.size())
    {
        spdlog::error("Version ack payload buffer overflow reading server version");
        return;
    }

    serverVersion = std::string(payload.begin() + offset, payload.begin() + offset + serverVersionLen);
    offset += serverVersionLen;

    // Platform (string with length prefix)
    if (offset >= payload.size())
    {
        spdlog::error("Version ack payload buffer overflow reading platform length");
        return;
    }
    uint8_t platformLen = readUint8(payload, offset);

    if (offset + platformLen > payload.size())
    {
        spdlog::error("Version ack payload buffer overflow reading platform");
        return;
    }

    platform = std::string(payload.begin() + offset, payload.begin() + offset + platformLen);
    offset += platformLen;

    // Reason (if present)
    reason.clear();
    if (hasReason)
    {
        if (offset >= payload.size())
        {
            spdlog::error("Version ack payload buffer overflow reading reason length");
            return;
        }
        uint8_t reasonLen = readUint8(payload, offset);

        if (offset + reasonLen > payload.size())
        {
            spdlog::error("Version ack payload buffer overflow reading reason");
            return;
        }

        reason = std::string(payload.begin() + offset, payload.begin() + offset + reasonLen);
    }
}

} // namespace bitchat
