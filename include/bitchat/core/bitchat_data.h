#pragma once

#include "bitchat/protocol/packet.h"
#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace bitchat
{

// BitchatData: Centralized data storage for shared state across services
class BitchatData
{
public:
    // Singleton access
    static std::shared_ptr<BitchatData> shared();

    ~BitchatData() = default;

    // Copy constructor and assignment operator disabled for thread safety
    BitchatData(const BitchatData &) = delete;
    BitchatData &operator=(const BitchatData &) = delete;

    // Identity and Basic Info

    // Local peer ID
    void setPeerID(const std::string &peerID);
    std::string getPeerID() const;

    // Nickname
    void setNickname(const std::string &nickname);
    std::string getNickname() const;

    // Channel Management

    // Current channel
    void setCurrentChannel(const std::string &channel);
    std::string getCurrentChannel() const;

    // Peer Management

    // Peers list
    void setPeers(const std::vector<BitchatPeer> &peers);
    std::vector<BitchatPeer> getPeers() const;
    void addPeer(const BitchatPeer &peer);
    void removePeer(const std::string &peerID);
    void updatePeer(const BitchatPeer &peer);
    size_t getPeersCount() const;
    bool isPeerOnline(const std::string &peerID) const;
    std::optional<BitchatPeer> getPeerInfo(const std::string &peerID) const;

    // Message History

    // Message history by channel
    void addMessageToHistory(const BitchatMessage &message, const std::string &channel);
    std::vector<BitchatMessage> getMessageHistory(const std::string &channel) const;
    void clearMessageHistory(const std::string &channel);
    void clearAllMessageHistory();

    // Processed Messages Tracking

    // Track processed messages to avoid duplicates
    bool wasMessageProcessed(const std::string &messageID) const;
    void markMessageProcessed(const std::string &messageID);
    void clearProcessedMessages();

    // Generate unique message ID
    std::string generateMessageID() const;

    // Cleanup stale data
    void cleanupStalePeers();
    void cleanupOldMessages(size_t maxHistorySize);
    void cleanupOldProcessedMessages(size_t maxProcessedSize);

private:
    // Private constructor for singleton
    BitchatData();

    // Static instance
    static std::shared_ptr<BitchatData> instance;
    static std::mutex instanceMutex;

    // Identity and Basic Info
    mutable std::mutex identityMutex;
    std::string peerID;
    std::string nickname;

    // Channel Management
    mutable std::mutex currentChannelMutex;
    std::string currentChannel;

    // Peer Management
    mutable std::mutex peersMutex;
    std::vector<BitchatPeer> peers;

    // Message History
    mutable std::mutex messageHistoryMutex;
    std::map<std::string, std::vector<BitchatMessage>> messageHistory;

    // Processed Messages Tracking
    mutable std::mutex processedMessagesMutex;
    std::set<std::string> processedMessages;
};

} // namespace bitchat
