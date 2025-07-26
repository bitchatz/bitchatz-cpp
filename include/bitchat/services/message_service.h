#pragma once

#include "bitchat/core/bitchat_data.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/ui/ui_interface.h"
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

// MessageService: Centralized packet processing and message management
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

    // Start identity announce
    void startIdentityAnnounce();

    // Peer joined
    void peerJoined(const std::string &peerID, const std::string &nickname);

    // Peer left
    void peerLeft(const std::string &peerID, const std::string &nickname);

    // Peer connected
    void peerConnected(const std::string &peripheralID);

    // Peer disconnected
    void peerDisconnected(const std::string &peripheralID);

    // Centralized packet processing - main entry point for all packets
    void processPacket(const BitchatPacket &packet, const std::string &peripheralID);

    // Utility methods
    BitchatPacket createMessagePacket(const BitchatMessage &message);
    BitchatPacket createAnnouncePacket();
    BitchatPacket createChannelAnnouncePacket(const std::string &channel, bool joining);
    BitchatPacket createVersionHelloPacket();

    // Set callbacks for message events
    using MessageReceivedCallback = std::function<void(const BitchatMessage &)>;
    using ChannelJoinedCallback = std::function<void(const std::string &)>;
    using ChannelLeftCallback = std::function<void(const std::string &)>;
    using PeerJoinedCallback = std::function<void(const std::string &, const std::string &)>;
    using PeerLeftCallback = std::function<void(const std::string &, const std::string &)>;
    using PeerConnectedCallback = std::function<void(const std::string &)>;
    using PeerDisconnectedCallback = std::function<void(const std::string &)>;

    void setMessageReceivedCallback(MessageReceivedCallback callback);
    void setChannelJoinedCallback(ChannelJoinedCallback callback);
    void setChannelLeftCallback(ChannelLeftCallback callback);
    void setPeerJoinedCallback(PeerJoinedCallback callback);
    void setPeerLeftCallback(PeerLeftCallback callback);
    void setPeerConnectedCallback(PeerConnectedCallback callback);
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback);

private:
    // Dependencies
    std::shared_ptr<NetworkService> networkService;
    std::shared_ptr<CryptoService> cryptoService;
    std::shared_ptr<NoiseService> noiseService;

    // Message event callbacks
    MessageReceivedCallback messageReceivedCallback;
    ChannelJoinedCallback channelJoinedCallback;
    ChannelLeftCallback channelLeftCallback;
    PeerJoinedCallback peerJoinedCallback;
    PeerLeftCallback peerLeftCallback;
    PeerConnectedCallback peerConnectedCallback;
    PeerDisconnectedCallback peerDisconnectedCallback;

    // Message-related packet processing
    void processMessagePacket(const BitchatPacket &packet);
    void processChannelAnnouncePacket(const BitchatPacket &packet);

    // Network-related packet processing
    void processAnnouncePacket(const BitchatPacket &packet, const std::string &peripheralID);
    void processLeavePacket(const BitchatPacket &packet);

    // Noise protocol packet processing
    void processNoiseHandshakeInitPacket(const BitchatPacket &packet);
    void processNoiseHandshakeRespPacket(const BitchatPacket &packet);
    void processNoiseEncryptedPacket(const BitchatPacket &packet);
    void processNoiseIdentityAnnouncePacket(const BitchatPacket &packet);

    // Utility methods
    std::string generateMessageID() const;

    // Helper methods
    bool shouldProcessPacket(const BitchatPacket &packet) const;
    void markPacketProcessed(const BitchatPacket &packet);
};

} // namespace bitchat
