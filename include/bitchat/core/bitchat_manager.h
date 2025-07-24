#pragma once

#include "bitchat/helpers/compression_helper.h"
#include "bitchat/noise/noise_session.h"
#include "bitchat/platform/bluetooth_factory.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/message_service.h"
#include "bitchat/services/network_service.h"
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
    BitchatManager();
    ~BitchatManager();

    // Initialize the manager
    bool initialize(std::shared_ptr<BluetoothAnnounceRunner> announceRunner = nullptr, std::shared_ptr<CleanupRunner> cleanupRunner = nullptr);

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

    // User operations
    void setNickname(const std::string &nickname);

    // Getters
    std::string getCurrentChannel() const;
    std::string getNickname() const;
    std::string getPeerID() const;
    std::vector<BitchatPeer> getPeers() const;

    // Setters
    void setPeerID(const std::string &peerID);
    std::vector<BitchatMessage> getMessageHistory() const;
    size_t getPeersCount() const;

    // Status
    bool isReady() const;

    // Set callbacks for UI updates
    using MessageCallback = std::function<void(const BitchatMessage &)>;
    using PeerCallback = std::function<void(const std::string &, const std::string &)>;
    using StatusCallback = std::function<void(const std::string &)>;

    void setMessageCallback(MessageCallback callback);
    void setPeerJoinedCallback(PeerCallback callback);
    void setPeerLeftCallback(PeerCallback callback);
    void setStatusCallback(StatusCallback callback);

private:
    // Core services
    std::shared_ptr<NetworkService> networkService;
    std::shared_ptr<MessageService> messageService;
    std::shared_ptr<CryptoService> cryptoService;
    std::shared_ptr<noise::NoiseSessionManager> noiseSessionManager;

    // Runners
    std::shared_ptr<BluetoothAnnounceRunner> announceRunner;
    std::shared_ptr<CleanupRunner> cleanupRunner;

    // Bluetooth interface
    std::shared_ptr<BluetoothInterface> bluetoothInterface;

    // State
    bool initialized = false;
    bool started = false;

    // Callbacks
    MessageCallback messageCallback;
    PeerCallback peerJoinedCallback;
    PeerCallback peerLeftCallback;
    StatusCallback statusCallback;

    // Internal methods
    void setupCallbacks();
    void onMessageReceived(const BitchatMessage &message);
    void onPeerJoined(const std::string &peerID, const std::string &nickname);
    void onPeerLeft(const std::string &peerID, const std::string &nickname);
    void onStatusUpdate(const std::string &status);
    void processNoisePacket(const BitchatPacket &packet);
    void sendNoiseIdentityAnnounce();
};

} // namespace bitchat
