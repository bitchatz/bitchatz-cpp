#pragma once

#include "bitchat/compression/compression_manager.h"
#include "bitchat/core/message_manager.h"
#include "bitchat/core/network_manager.h"
#include "bitchat/crypto/crypto_manager.h"
#include "bitchat/noise/noise_session.h"
#include "bitchat/platform/bluetooth_factory.h"
#include "bitchat/protocol/packet.h"
#include <memory>

namespace bitchat
{

// BitchatManager: main orchestrator that coordinates all components
class BitchatManager
{
public:
    BitchatManager();
    ~BitchatManager();

    // Initialize the manager
    bool initialize();

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
    std::string getPeerId() const;
    std::map<std::string, OnlinePeer> getOnlinePeers() const;

    // Setters
    void setPeerId(const std::string &peerId);
    std::vector<BitchatMessage> getMessageHistory() const;
    size_t getConnectedPeersCount() const;

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
    // Core managers
    std::shared_ptr<NetworkManager> networkManager;
    std::shared_ptr<MessageManager> messageManager;
    std::shared_ptr<CryptoManager> cryptoManager;
    std::shared_ptr<CompressionManager> compressionManager;
    std::shared_ptr<noise::NoiseSessionManager> noiseSessionManager;

    // Bluetooth interface
    std::unique_ptr<BluetoothInterface> bluetoothInterface;

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
    void onPeerJoined(const std::string &peerId, const std::string &nickname);
    void onPeerLeft(const std::string &peerId, const std::string &nickname);
    void onStatusUpdate(const std::string &status);
    void processNoisePacket(const BitchatPacket &packet);
    void sendNoiseIdentityAnnounce();
};

} // namespace bitchat
