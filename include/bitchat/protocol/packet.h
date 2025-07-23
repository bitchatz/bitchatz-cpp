#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bitchat
{

// Packet type constants
constexpr uint8_t PKT_VERSION = 1;
constexpr uint8_t PKT_TYPE_ANNOUNCE = 0x01;
constexpr uint8_t PKT_TYPE_KEY_EXCHANGE = 0x02;
constexpr uint8_t PKT_TYPE_LEAVE = 0x03;
constexpr uint8_t PKT_TYPE_MESSAGE = 0x04;
constexpr uint8_t PKT_TYPE_FRAGMENT_START = 0x05;
constexpr uint8_t PKT_TYPE_FRAGMENT_CONTINUE = 0x06;
constexpr uint8_t PKT_TYPE_FRAGMENT_END = 0x07;
constexpr uint8_t PKT_TYPE_CHANNEL_ANNOUNCE = 0x08;
constexpr uint8_t PKT_TYPE_DELIVERY_ACK = 0x0A;
constexpr uint8_t PKT_TYPE_DELIVERY_STATUS_REQUEST = 0x0B;
constexpr uint8_t PKT_TYPE_READ_RECEIPT = 0x0C;

// Noise Protocol messages
constexpr uint8_t PKT_TYPE_NOISE_HANDSHAKE_INIT = 0x10;
constexpr uint8_t PKT_TYPE_NOISE_HANDSHAKE_RESP = 0x11;
constexpr uint8_t PKT_TYPE_NOISE_ENCRYPTED = 0x12;
constexpr uint8_t PKT_TYPE_NOISE_IDENTITY_ANNOUNCE = 0x13;
constexpr uint8_t PKT_TYPE_CHANNEL_KEY_VERIFY_REQUEST = 0x14;
constexpr uint8_t PKT_TYPE_CHANNEL_KEY_VERIFY_RESPONSE = 0x15;
constexpr uint8_t PKT_TYPE_CHANNEL_PASSWORD_UPDATE = 0x16;
constexpr uint8_t PKT_TYPE_CHANNEL_METADATA = 0x17;

// Protocol version negotiation
constexpr uint8_t PKT_TYPE_VERSION_HELLO = 0x20;
constexpr uint8_t PKT_TYPE_VERSION_ACK = 0x21;

// Packet flags
constexpr uint8_t FLAG_HAS_RECIPIENT = 0x01;
constexpr uint8_t FLAG_HAS_SIGNATURE = 0x02;
constexpr uint8_t FLAG_IS_COMPRESSED = 0x04;

// Default TTL
constexpr uint8_t PKT_TTL = 7;

// BitchatPacket: represents a protocol packet sent via Bluetooth
class BitchatPacket
{
public:
    BitchatPacket() = default;
    BitchatPacket(uint8_t type, const std::vector<uint8_t> &payload);

    // Getters
    uint8_t getVersion() const { return version; }
    uint8_t getType() const { return type; }
    uint8_t getTtl() const { return ttl; }
    uint64_t getTimestamp() const { return timestamp; }
    uint8_t getFlags() const { return flags; }
    uint16_t getPayloadLength() const { return payloadLength; }
    const std::vector<uint8_t> &getSenderId() const { return senderId; }
    const std::vector<uint8_t> &getRecipientID() const { return recipientID; }
    const std::vector<uint8_t> &getPayload() const { return payload; }
    const std::vector<uint8_t> &getSignature() const { return signature; }

    // Setters
    void setVersion(uint8_t v) { version = v; }
    void setType(uint8_t t) { type = t; }
    void setTtl(uint8_t t) { ttl = t; }
    void setTimestamp(uint64_t ts) { timestamp = ts; }
    void setFlags(uint8_t f) { flags = f; }
    void setPayloadLength(uint16_t len) { payloadLength = len; }
    void setSenderId(const std::vector<uint8_t> &id) { senderId = id; }
    void setRecipientID(const std::vector<uint8_t> &id) { recipientID = id; }
    void setPayload(const std::vector<uint8_t> &p)
    {
        payload = p;
        payloadLength = static_cast<uint16_t>(p.size());
    }
    void setSignature(const std::vector<uint8_t> &sig) { signature = sig; }

    // Utility methods
    std::string getTypeString() const;
    bool hasRecipient() const { return flags & FLAG_HAS_RECIPIENT; }
    bool hasSignature() const { return flags & FLAG_HAS_SIGNATURE; }
    bool isCompressed() const { return flags & FLAG_IS_COMPRESSED; }
    void setHasRecipient(bool has)
    {
        if (has)
            flags |= FLAG_HAS_RECIPIENT;
        else
            flags &= ~FLAG_HAS_RECIPIENT;
    }
    void setHasSignature(bool has)
    {
        if (has)
            flags |= FLAG_HAS_SIGNATURE;
        else
            flags &= ~FLAG_HAS_SIGNATURE;
    }
    void setCompressed(bool compressed)
    {
        if (compressed)
            flags |= FLAG_IS_COMPRESSED;
        else
            flags &= ~FLAG_IS_COMPRESSED;
    }

    // Validation
    bool isValid() const;
    size_t getTotalSize() const;

private:
    uint8_t version = PKT_VERSION;
    uint8_t type = 0;
    uint8_t ttl = PKT_TTL;
    uint64_t timestamp = 0;
    uint8_t flags = 0;
    uint16_t payloadLength = 0;
    std::vector<uint8_t> senderId;
    std::vector<uint8_t> recipientID;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> signature;
};

// BitchatMessage: represents a chat message
class BitchatMessage
{
public:
    BitchatMessage() = default;
    BitchatMessage(const std::string &sender, const std::string &content, const std::string &channel = "");

    // Getters
    const std::string &getId() const { return id; }
    const std::string &getSender() const { return sender; }
    const std::string &getContent() const { return content; }
    uint64_t getTimestamp() const { return timestamp; }
    bool isRelay() const { return isRelayFlag; }
    const std::string &getOriginalSender() const { return originalSender; }
    bool isPrivate() const { return isPrivateFlag; }
    const std::string &getRecipientNickname() const { return recipientNickname; }
    const std::vector<uint8_t> &getSenderPeerID() const { return senderPeerID; }
    const std::vector<std::string> &getMentions() const { return mentions; }
    const std::string &getChannel() const { return channel; }
    const std::vector<uint8_t> &getEncryptedContent() const { return encryptedContent; }
    bool isEncrypted() const { return isEncryptedFlag; }

    // Setters
    void setId(const std::string &i) { id = i; }
    void setSender(const std::string &s) { sender = s; }
    void setContent(const std::string &c) { content = c; }
    void setTimestamp(uint64_t ts) { timestamp = ts; }
    void setRelay(bool relay) { isRelayFlag = relay; }
    void setOriginalSender(const std::string &os) { originalSender = os; }
    void setPrivate(bool priv) { isPrivateFlag = priv; }
    void setRecipientNickname(const std::string &rn) { recipientNickname = rn; }
    void setSenderPeerID(const std::vector<uint8_t> &spid) { senderPeerID = spid; }
    void setMentions(const std::vector<std::string> &m) { mentions = m; }
    void setChannel(const std::string &c) { channel = c; }
    void setEncryptedContent(const std::vector<uint8_t> &ec) { encryptedContent = ec; }
    void setEncrypted(bool enc) { isEncryptedFlag = enc; }

    // Utility methods
    void addMention(const std::string &mention);
    bool hasMention(const std::string &mention) const;
    std::string getDisplayContent() const;

private:
    std::string id;
    std::string sender;
    std::string content;
    uint64_t timestamp = 0;
    bool isRelayFlag = false;
    std::string originalSender;
    bool isPrivateFlag = false;
    std::string recipientNickname;
    std::vector<uint8_t> senderPeerID;
    std::vector<std::string> mentions;
    std::string channel;
    std::vector<uint8_t> encryptedContent;
    bool isEncryptedFlag = false;
};

// BitchatPeer: represents a peer in the network
class BitchatPeer
{
public:
    BitchatPeer() = default;
    BitchatPeer(const std::vector<uint8_t> &peerId, const std::string &nickname);

    // Getters
    const std::string &getNickname() const { return nickname; }
    const std::string &getChannel() const { return channel; }
    const std::vector<uint8_t> &getPeerId() const { return peerId; }
    time_t getLastSeen() const { return lastSeen; }
    int getRSSI() const { return RSSI; }
    bool hasAnnounced() const { return hasAnnouncedFlag; }
    const std::string &getPeripheralUUID() const { return peripheralUUID; }

    // Setters
    void setNickname(const std::string &n) { nickname = n; }
    void setChannel(const std::string &c) { channel = c; }
    void setPeerId(const std::vector<uint8_t> &pid) { peerId = pid; }
    void setLastSeen(time_t ls) { lastSeen = ls; }
    void setRSSI(int r) { RSSI = r; }
    void setHasAnnounced(bool announced) { hasAnnouncedFlag = announced; }
    void setPeripheralUUID(const std::string &uuid) { peripheralUUID = uuid; }

    // Utility methods
    void updateLastSeen();
    bool isStale(time_t timeout = 180) const;
    std::string getDisplayName() const;

private:
    std::string nickname;
    std::string channel;
    std::vector<uint8_t> peerId;
    time_t lastSeen = 0;
    int RSSI = -100;
    bool hasAnnouncedFlag = false;
    std::string peripheralUUID;
};

} // namespace bitchat
