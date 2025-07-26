#pragma once

#include "bitchat/core/bitchat_data.h"
#include "bitchat/helpers/compression_helper.h"
#include "bitchat/platform/bluetooth_factory.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/message_service.h"
#include "bitchat/services/network_service.h"
#include "bitchat/services/noise_service.h"
#include <memory>

namespace bitchat
{

// Forward declarations
class BluetoothAnnounceRunner;
class CleanupRunner;

// BitchatManager: Main orchestrator that coordinates all components
class BitchatManager
{
public:
    // Singleton access
    static std::shared_ptr<BitchatManager> shared();

    BitchatManager();
    ~BitchatManager();

    // Copy constructor and assignment operator disabled for thread safety
    BitchatManager(const BitchatManager &) = delete;
    BitchatManager &operator=(const BitchatManager &) = delete;

    // Initialize the manager
    bool initialize(
        std::shared_ptr<NetworkService> networkService,
        std::shared_ptr<MessageService> messageService,
        std::shared_ptr<CryptoService> cryptoService,
        std::shared_ptr<NoiseService> noiseService,
        std::shared_ptr<BluetoothAnnounceRunner> announceRunner,
        std::shared_ptr<CleanupRunner> cleanupRunner);

    // Start the manager
    bool start();

    // Stop the manager
    void stop();

    // Message operations
    bool sendMessage(const std::string &content);
    bool sendPrivateMessage(const std::string &content, const std::string &recipientNickname);

    // Channel operations
    void joinChannel(const std::string &channel);
    void leaveChannel();

    // Nickname operations
    void changeNickname(const std::string &nickname);

    // Status
    bool isReady() const;

    // Service getters
    std::shared_ptr<NetworkService> getNetworkService() const;
    std::shared_ptr<MessageService> getMessageService() const;
    std::shared_ptr<CryptoService> getCryptoService() const;
    std::shared_ptr<NoiseService> getNoiseService() const;

    // Set callbacks for UI updates
    using MessageCallback = std::function<void(const BitchatMessage &)>;
    using PeerJoinedCallback = std::function<void(const std::string &, const std::string &)>;
    using PeerLeftCallback = std::function<void(const std::string &, const std::string &)>;
    using PeerConnectedCallback = std::function<void(const std::string &)>;
    using PeerDisconnectedCallback = std::function<void(const std::string &)>;
    using StatusCallback = std::function<void(const std::string &)>;
    using ChannelJoinedCallback = std::function<void(const std::string &)>;
    using ChannelLeftCallback = std::function<void(const std::string &)>;

    void setMessageCallback(MessageCallback callback);
    void setPeerJoinedCallback(PeerJoinedCallback callback);
    void setPeerLeftCallback(PeerLeftCallback callback);
    void setPeerConnectedCallback(PeerConnectedCallback callback);
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback);
    void setStatusCallback(StatusCallback callback);
    void setChannelJoinedCallback(ChannelJoinedCallback callback);
    void setChannelLeftCallback(ChannelLeftCallback callback);

private:
    // Static instance
    static std::shared_ptr<BitchatManager> instance;

    // Core services
    std::shared_ptr<NetworkService> networkService;
    std::shared_ptr<MessageService> messageService;
    std::shared_ptr<CryptoService> cryptoService;
    std::shared_ptr<NoiseService> noiseService;

    // Runners
    std::shared_ptr<BluetoothAnnounceRunner> announceRunner;
    std::shared_ptr<CleanupRunner> cleanupRunner;

    // Bluetooth interface
    std::shared_ptr<BluetoothInterface> bluetoothInterface;

    // Callbacks
    MessageCallback messageCallback;
    PeerJoinedCallback peerJoinedCallback;
    PeerLeftCallback peerLeftCallback;
    PeerConnectedCallback peerConnectedCallback;
    PeerDisconnectedCallback peerDisconnectedCallback;
    StatusCallback statusCallback;
    ChannelJoinedCallback channelJoinedCallback;
    ChannelLeftCallback channelLeftCallback;

    // Internal methods
    void setupCallbacks();
    void onMessageReceived(const BitchatMessage &message);
    void onPeerJoined(const std::string &peerID, const std::string &nickname);
    void onPeerLeft(const std::string &peerID, const std::string &nickname);
    void onPeerConnected(const std::string &peripheralID);
    void onPeerDisconnected(const std::string &peripheralID);
    void onStatusUpdate(const std::string &status);
    void onChannelJoined(const std::string &channel);
    void onChannelLeft(const std::string &channel);
};

} // namespace bitchat
