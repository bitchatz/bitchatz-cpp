#include "bitchat/protocol/packet.h"
#include "bitchat/helpers/protocol_helper.h"
#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>

#ifdef __APPLE__
#include <uuid/uuid.h>
#endif

namespace bitchat
{

// BitchatPacket implementations
BitchatPacket::BitchatPacket(uint8_t type, const std::vector<uint8_t> &payload)
    : type(type)
    , payloadLength(static_cast<uint16_t>(payload.size()))
    , payload(payload)
{
    timestamp = ProtocolHelper::getCurrentTimestamp();
}

std::string BitchatPacket::getTypeString() const
{
    switch (type)
    {
    case PKT_TYPE_ANNOUNCE:
        return "ANNOUNCE";
    case PKT_TYPE_LEAVE:
        return "LEAVE";
    case PKT_TYPE_MESSAGE:
        return "MESSAGE";
    case PKT_TYPE_FRAGMENT_START:
        return "FRAGMENT_START";
    case PKT_TYPE_FRAGMENT_CONTINUE:
        return "FRAGMENT_CONTINUE";
    case PKT_TYPE_FRAGMENT_END:
        return "FRAGMENT_END";
    case PKT_TYPE_CHANNEL_ANNOUNCE:
        return "CHANNEL_ANNOUNCE";
    case PKT_TYPE_DELIVERY_ACK:
        return "DELIVERY_ACK";
    case PKT_TYPE_DELIVERY_STATUS_REQUEST:
        return "DELIVERY_STATUS_REQUEST";
    case PKT_TYPE_READ_RECEIPT:
        return "READ_RECEIPT";
    case PKT_TYPE_NOISE_HANDSHAKE_INIT:
        return "NOISE_HANDSHAKE_INIT";
    case PKT_TYPE_NOISE_HANDSHAKE_RESP:
        return "NOISE_HANDSHAKE_RESP";
    case PKT_TYPE_NOISE_ENCRYPTED:
        return "NOISE_ENCRYPTED";
    case PKT_TYPE_NOISE_IDENTITY_ANNOUNCE:
        return "NOISE_IDENTITY_ANNOUNCE";
    case PKT_TYPE_CHANNEL_KEY_VERIFY_REQUEST:
        return "CHANNEL_KEY_VERIFY_REQUEST";
    case PKT_TYPE_CHANNEL_KEY_VERIFY_RESPONSE:
        return "CHANNEL_KEY_VERIFY_RESPONSE";
    case PKT_TYPE_CHANNEL_PASSWORD_UPDATE:
        return "CHANNEL_PASSWORD_UPDATE";
    case PKT_TYPE_CHANNEL_METADATA:
        return "CHANNEL_METADATA";
    case PKT_TYPE_VERSION_HELLO:
        return "VERSION_HELLO";
    case PKT_TYPE_VERSION_ACK:
        return "VERSION_ACK";
    default:
        return "UNKNOWN";
    }
}

bool BitchatPacket::isValid() const
{
    // Basic validation
    if (version != PKT_VERSION)
    {
        return false;
    }

    if (payloadLength != payload.size())
    {
        return false;
    }

    if (timestamp == 0)
    {
        return false;
    }

    return true;
}

size_t BitchatPacket::getTotalSize() const
{
    size_t size = 13; // Header size (version + type + ttl + timestamp + flags + payloadLength)
    size += 8;        // SenderId

    if (hasRecipient())
    {
        size += 8; // RecipientID
    }

    size += payloadLength; // Payload

    if (hasSignature())
    {
        size += 64; // Signature
    }

    return size;
}

// BitchatMessage implementations
BitchatMessage::BitchatMessage(const std::string &sender, const std::string &content, const std::string &channel)
    : sender(sender)
    , content(content)
    , channel(channel)
{
    timestamp = ProtocolHelper::getCurrentTimestamp();
    id = ProtocolHelper::uuidv4();
}

void BitchatMessage::addMention(const std::string &mention)
{
    if (!hasMention(mention))
    {
        mentions.push_back(mention);
    }
}

bool BitchatMessage::hasMention(const std::string &mention) const
{
    return std::find(mentions.begin(), mentions.end(), mention) != mentions.end();
}

std::string BitchatMessage::getDisplayContent() const
{
    if (isEncryptedFlag)
    {
        return "[ENCRYPTED]";
    }
    return content;
}

// OnlinePeer implementations
OnlinePeer::OnlinePeer(const std::string &nickname, const std::vector<uint8_t> &peerId)
    : nick(nickname)
    , peerId(peerId)
{
    updateLastSeen();
}

void OnlinePeer::updateLastSeen()
{
    lastSeen = std::time(nullptr);
}

bool OnlinePeer::isStale(time_t timeout) const
{
    return (std::time(nullptr) - lastSeen) > timeout;
}

std::string OnlinePeer::getDisplayName() const
{
    if (nick.empty())
    {
        return ProtocolHelper::toHexCompact(peerId);
    }
    return nick;
}

} // namespace bitchat
