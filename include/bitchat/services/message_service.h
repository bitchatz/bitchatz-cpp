#pragma once

#include "bitchat/core/bitchat_data.h"
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
class NetworkService;
class CryptoService;
class NoiseService;

// MessageService: Manages chat messages, history, and message processing
class MessageService
{
public:
    MessageService();
    ~MessageService() = default;

    // Initialize the message service
    bool initialize(std::shared_ptr<NetworkService> networkService, std::shared_ptr<CryptoService> cryptoService, std::shared_ptr<NoiseService> noiseService);

    // Send a message to a channel
    bool sendMessage(const std::string &content, const std::string &channel = "");

    // Send a private message to a specific peer
    bool sendPrivateMessage(const std::string &content, const std::string &recipientNickname);

    // Join a channel
    void joinChannel(const std::string &channel);

    // Leave current channel
    void leaveChannel();

    // Set callbacks
    using MessageReceivedCallback = std::function<void(const BitchatMessage &)>;
    using ChannelJoinedCallback = std::function<void(const std::string &)>;
    using ChannelLeftCallback = std::function<void(const std::string &)>;

    void setMessageReceivedCallback(MessageReceivedCallback callback);
    void setChannelJoinedCallback(ChannelJoinedCallback callback);
    void setChannelLeftCallback(ChannelLeftCallback callback);

    // Process incoming packet
    void processPacket(const BitchatPacket &packet, const std::string &peripheralID);

    // Check if service is ready
    bool isReady() const;

private:
    // Dependencies
    std::shared_ptr<NetworkService> networkService;
    std::shared_ptr<CryptoService> cryptoService;
    std::shared_ptr<NoiseService> noiseService;

    // Callbacks
    MessageReceivedCallback messageReceivedCallback;
    ChannelJoinedCallback channelJoinedCallback;
    ChannelLeftCallback channelLeftCallback;

    // Internal methods
    void onPacketReceived(const BitchatPacket &packet, const std::string &peripheralID);
    void processMessagePacket(const BitchatPacket &packet);
    void processChannelAnnouncePacket(const BitchatPacket &packet);
    BitchatPacket createMessagePacket(const BitchatMessage &message);
    BitchatPacket createAnnouncePacket();
    BitchatPacket createChannelAnnouncePacket(const std::string &channel, bool joining);
    std::string generateMessageID() const;
};

} // namespace bitchat
