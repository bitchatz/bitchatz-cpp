#include "bitchat/core/bitchat_data.h"
#include "bitchat/core/constants.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/string_helper.h"
#include <algorithm>
#include <spdlog/spdlog.h>

namespace bitchat
{

// Static instance initialization
std::shared_ptr<BitchatData> BitchatData::instance = nullptr;
std::mutex BitchatData::instanceMutex;

std::shared_ptr<BitchatData> BitchatData::shared()
{
    std::lock_guard<std::mutex> lock(instanceMutex);

    if (!instance)
    {
        instance = std::shared_ptr<BitchatData>(new BitchatData());
    }

    return instance;
}

BitchatData::BitchatData()
{
    // Initialize with default values
    nickname = StringHelper::randomNickname();
    currentChannel = "";
}

// Identity and Basic Info

void BitchatData::setPeerID(const std::string &peerID)
{
    std::lock_guard<std::mutex> lock(identityMutex);
    this->peerID = peerID;
}

std::string BitchatData::getPeerID() const
{
    std::lock_guard<std::mutex> lock(identityMutex);
    return peerID;
}

void BitchatData::setNickname(const std::string &nickname)
{
    std::lock_guard<std::mutex> lock(identityMutex);
    this->nickname = nickname;
}

std::string BitchatData::getNickname() const
{
    std::lock_guard<std::mutex> lock(identityMutex);
    return nickname;
}

// Channel Management

void BitchatData::setCurrentChannel(const std::string &channel)
{
    std::lock_guard<std::mutex> lock(currentChannelMutex);
    currentChannel = channel;
}

std::string BitchatData::getCurrentChannel() const
{
    std::lock_guard<std::mutex> lock(currentChannelMutex);
    return currentChannel;
}

// Peer Management

void BitchatData::setPeers(const std::vector<BitchatPeer> &peers)
{
    std::lock_guard<std::mutex> lock(peersMutex);
    this->peers = peers;
}

std::vector<BitchatPeer> BitchatData::getPeers() const
{
    std::lock_guard<std::mutex> lock(peersMutex);
    return peers;
}

void BitchatData::addPeer(const BitchatPeer &peer)
{
    std::lock_guard<std::mutex> lock(peersMutex);

    // Check if peer already exists
    // clang-format off
    auto it = std::find_if(peers.begin(), peers.end(), [&peer](const BitchatPeer &p) {
        return p.getPeerID() == peer.getPeerID();
    });
    // clang-format on

    if (it == peers.end())
    {
        // Add new peer
        peers.push_back(peer);
    }
    else
    {
        // Update existing peer
        *it = peer;
    }
}

void BitchatData::removePeer(const std::string &peerID)
{
    std::lock_guard<std::mutex> lock(peersMutex);

    // clang-format off
    peers.erase(std::remove_if(peers.begin(), peers.end(), [&peerID](const BitchatPeer &peer) {
        return peer.getPeerID() == peerID;
    }), peers.end());
    // clang-format on
}

void BitchatData::updatePeer(const BitchatPeer &peer)
{
    std::lock_guard<std::mutex> lock(peersMutex);

    // clang-format off
    auto it = std::find_if(peers.begin(), peers.end(), [&peer](const BitchatPeer &p) {
        return p.getPeerID() == peer.getPeerID();
    });
    // clang-format on

    if (it != peers.end())
    {
        // Update existing peer
        *it = peer;
    }
    else
    {
        // Add new peer if not found
        peers.push_back(peer);
    }
}

size_t BitchatData::getPeersCount() const
{
    std::lock_guard<std::mutex> lock(peersMutex);
    return peers.size();
}

bool BitchatData::isPeerOnline(const std::string &peerID) const
{
    std::lock_guard<std::mutex> lock(peersMutex);

    // clang-format off
    auto it = std::find_if(peers.begin(), peers.end(), [&peerID](const BitchatPeer &peer) {
        return peer.getPeerID() == peerID;
    });
    // clang-format on

    if (it != peers.end())
    {
        return !it->isStale(constants::PEER_TIMEOUT_SECONDS);
    }

    return false;
}

std::optional<BitchatPeer> BitchatData::getPeerInfo(const std::string &peerID) const
{
    std::lock_guard<std::mutex> lock(peersMutex);

    // clang-format off
    auto it = std::find_if(peers.begin(), peers.end(), [&peerID](const BitchatPeer &peer) {
        return peer.getPeerID() == peerID;
    });
    // clang-format on

    if (it != peers.end())
    {
        return *it;
    }

    return std::nullopt;
}

// Message History

void BitchatData::addMessageToHistory(const BitchatMessage &message, const std::string &channel)
{
    std::lock_guard<std::mutex> lock(messageHistoryMutex);

    std::string targetChannel = channel.empty() ? currentChannel : channel;

    // Add message to history
    messageHistory[targetChannel].push_back(message);

    // Limit history size
    if (messageHistory[targetChannel].size() > constants::MAX_HISTORY_SIZE)
    {
        messageHistory[targetChannel].erase(messageHistory[targetChannel].begin());
    }
}

std::vector<BitchatMessage> BitchatData::getMessageHistory(const std::string &channel) const
{
    std::lock_guard<std::mutex> lock(messageHistoryMutex);

    std::string targetChannel = channel.empty() ? currentChannel : channel;

    auto it = messageHistory.find(targetChannel);
    if (it != messageHistory.end())
    {
        return it->second;
    }

    return {};
}

void BitchatData::clearMessageHistory(const std::string &channel)
{
    std::lock_guard<std::mutex> lock(messageHistoryMutex);

    if (channel.empty())
    {
        // Clear current channel history
        messageHistory.erase(currentChannel);
    }
    else
    {
        // Clear specific channel history
        messageHistory.erase(channel);
    }
}

void BitchatData::clearAllMessageHistory()
{
    std::lock_guard<std::mutex> lock(messageHistoryMutex);
    messageHistory.clear();
}

// Processed Messages Tracking

bool BitchatData::wasMessageProcessed(const std::string &messageID) const
{
    std::lock_guard<std::mutex> lock(processedMessagesMutex);
    return processedMessages.find(messageID) != processedMessages.end();
}

void BitchatData::markMessageProcessed(const std::string &messageID)
{
    std::lock_guard<std::mutex> lock(processedMessagesMutex);
    processedMessages.insert(messageID);

    // Limit processed messages size
    if (processedMessages.size() > constants::MAX_PROCESSED_MESSAGES)
    {
        // Remove oldest entries (simple approach: clear and rebuild)
        // In a more sophisticated implementation, you might want to use a queue
        processedMessages.clear();
    }
}

void BitchatData::clearProcessedMessages()
{
    std::lock_guard<std::mutex> lock(processedMessagesMutex);
    processedMessages.clear();
}

// Utility Methods

std::string BitchatData::generateMessageID() const
{
    // Generate a unique message ID using timestamp and UUID
    uint64_t timestamp = DateTimeHelper::getCurrentTimestamp();
    std::string uuid = StringHelper::createUUID();
    return std::to_string(timestamp) + "_" + uuid;
}

void BitchatData::cleanupStalePeers()
{
    std::lock_guard<std::mutex> lock(peersMutex);

    // clang-format off
    peers.erase(std::remove_if(peers.begin(), peers.end(), [](const BitchatPeer &peer) {
        return peer.isStale(constants::PEER_TIMEOUT_SECONDS);
    }), peers.end());
    // clang-format on
}

void BitchatData::cleanupOldMessages(size_t maxHistorySize)
{
    std::lock_guard<std::mutex> lock(messageHistoryMutex);

    for (auto &[channel, messages] : messageHistory)
    {
        if (messages.size() > maxHistorySize)
        {
            // Remove oldest messages
            size_t toRemove = messages.size() - maxHistorySize;
            messages.erase(messages.begin(), messages.begin() + toRemove);
        }
    }
}

void BitchatData::cleanupOldProcessedMessages(size_t maxProcessedSize)
{
    std::lock_guard<std::mutex> lock(processedMessagesMutex);

    if (processedMessages.size() > maxProcessedSize)
    {
        // Simple approach: clear all and start fresh
        // In a more sophisticated implementation, you might want to use a queue with timestamps
        processedMessages.clear();
    }
}

} // namespace bitchat
