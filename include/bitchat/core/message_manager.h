#pragma once

#include "bitchat/protocol/packet.h"
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace bitchat
{

// Forward declarations
class NetworkManager;
class CryptoManager;
class CompressionManager;

namespace noise
{
// Forward declarations
class NoiseSessionManager;
} // namespace noise

// MessageManager: Manages chat messages, history, and message processing
class MessageManager
{
public:
    MessageManager();
    ~MessageManager() = default;

    // Initialize the message manager
    bool initialize(std::shared_ptr<NetworkManager> networkManager, std::shared_ptr<CryptoManager> cryptoManager, std::shared_ptr<CompressionManager> compressionManager, std::shared_ptr<noise::NoiseSessionManager> noiseSessionManager);

    // Send a message to a channel
    bool sendMessage(const std::string &content, const std::string &channel = "");

    // Send a private message to a specific peer
    bool sendPrivateMessage(const std::string &content, const std::string &recipientNickname);

    // Join a channel
    void joinChannel(const std::string &channel);

    // Leave current channel
    void leaveChannel();

    // Get current channel
    std::string getCurrentChannel() const;

    // Get message history for current channel
    std::vector<BitchatMessage> getMessageHistory() const;

    // Get message history for a specific channel
    std::vector<BitchatMessage> getMessageHistory(const std::string &channel) const;

    // Clear message history
    void clearMessageHistory();

    // Set nickname
    void setNickname(const std::string &nickname);

    // Get nickname
    std::string getNickname() const;

    // Set callbacks
    using MessageReceivedCallback = std::function<void(const BitchatMessage &)>;
    using ChannelJoinedCallback = std::function<void(const std::string &)>;
    using ChannelLeftCallback = std::function<void(const std::string &)>;

    void setMessageReceivedCallback(MessageReceivedCallback callback);
    void setChannelJoinedCallback(ChannelJoinedCallback callback);
    void setChannelLeftCallback(ChannelLeftCallback callback);

    // Process incoming packet
    void processPacket(const BitchatPacket &packet);

    // Check if manager is ready
    bool isReady() const;

private:
    // Dependencies
    std::shared_ptr<NetworkManager> networkManager;
    std::shared_ptr<CryptoManager> cryptoManager;
    std::shared_ptr<CompressionManager> compressionManager;
    std::shared_ptr<noise::NoiseSessionManager> noiseSessionManager;

    // State
    std::string nickname;
    std::string currentChannel;
    std::map<std::string, std::vector<BitchatMessage>> messageHistory;
    std::set<std::string> processedMessages;

    // Mutexes
    mutable std::mutex historyMutex;
    mutable std::mutex processedMutex;

    // Callbacks
    MessageReceivedCallback messageReceivedCallback;
    ChannelJoinedCallback channelJoinedCallback;
    ChannelLeftCallback channelLeftCallback;

    // Internal methods
    void onPacketReceived(const BitchatPacket &packet);
    void processMessagePacket(const BitchatPacket &packet);
    void processChannelAnnouncePacket(const BitchatPacket &packet);
    void addMessageToHistory(const BitchatMessage &message);
    bool wasMessageProcessed(const std::string &messageID);
    void markMessageProcessed(const std::string &messageID);
    BitchatPacket createMessagePacket(const BitchatMessage &message);
    BitchatPacket createAnnouncePacket();
    BitchatPacket createChannelAnnouncePacket(const std::string &channel, bool joining);
    std::string generateMessageID() const;

    // Constants
    static constexpr size_t MAX_HISTORY_SIZE = 1000;
    static constexpr size_t MAX_PROCESSED_MESSAGES = 1000;
};

} // namespace bitchat
