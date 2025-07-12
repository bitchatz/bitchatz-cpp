#pragma once

#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/crypto/crypto_manager.h"
#include "bitchat/compression/compression_manager.h"
#include "bitchat/protocol/packet_serializer.h"
#include "bitchat/protocol/packet.h"
#include <memory>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <atomic>

namespace bitchat {

// BitchatManager: main class that orchestrates the entire application
class BitchatManager {
public:
    BitchatManager();
    ~BitchatManager();

    // Initialize the manager
    bool initialize();
    
    // Start the manager (start Bluetooth, etc.)
    bool start();
    
    // Stop the manager
    void stop();
    
    // Send a message to the current channel
    bool sendMessage(const std::string& content);
    
    // Join a channel
    void joinChannel(const std::string& channel);
    
    // Set nickname
    void setNickname(const std::string& nickname);
    
    // Get current channel
    std::string getCurrentChannel() const;
    
    // Get nickname
    std::string getNickname() const;
    
    // Get peer ID
    std::string getPeerId() const;
    
    // Get online peers
    std::map<std::string, OnlinePeer> getOnlinePeers() const;
    
    // Get message history
    std::vector<BitchatMessage> getMessageHistory() const;
    
    // Check if manager is ready
    bool isReady() const;
    
    // Set callbacks for UI updates
    using MessageCallback = std::function<void(const BitchatMessage&)>;
    using PeerCallback = std::function<void(const std::string&, const std::string&)>;
    using StatusCallback = std::function<void(const std::string&)>;
    
    void setMessageCallback(MessageCallback callback);
    void setPeerJoinedCallback(PeerCallback callback);
    void setPeerLeftCallback(PeerCallback callback);
    void setStatusCallback(StatusCallback callback);

private:
    // Bluetooth interface
    std::unique_ptr<BluetoothInterface> bluetooth;
    
    // Managers
    std::unique_ptr<CryptoManager> cryptoManager;
    std::unique_ptr<CompressionManager> compressionManager;
    std::unique_ptr<PacketSerializer> packetSerializer;
    
    // State
    std::string peerId;
    std::string nickname;
    std::string currentChannel;
    std::map<std::string, OnlinePeer> onlinePeers;
    std::vector<BitchatMessage> messageHistory;
    std::set<std::string> processedMessages;
    
    // Threading
    std::atomic<bool> shouldExit;
    std::thread announceThread;
    std::thread cleanupThread;
    
    // Mutexes
    mutable std::mutex peersMutex;
    mutable std::mutex messagesMutex;
    mutable std::mutex processedMutex;
    
    // Callbacks
    MessageCallback messageCallback;
    PeerCallback peerJoinedCallback;
    PeerCallback peerLeftCallback;
    StatusCallback statusCallback;
    
    // Bluetooth event handlers
    void onPeerConnected(const std::string& peerId, const std::string& nickname);
    void onPeerDisconnected(const std::string& peerId);
    void onMessageReceived(const BitchatMessage& message);
    void onPacketReceived(const BitchatPacket& packet);
    
    // Internal methods
    void announceLoop();
    void cleanupLoop();
    void cleanupStalePeers();
    void processPacket(const BitchatPacket& packet);
    void relayPacket(const BitchatPacket& packet);
    bool wasMessageProcessed(const std::string& messageId);
    void markMessageProcessed(const std::string& messageId);
    void logMessage(const std::string& message);

    // Constants
    static constexpr int ANNOUNCE_INTERVAL = 15; // seconds
    static constexpr int CLEANUP_INTERVAL = 30; // seconds
    static constexpr int PEER_TIMEOUT = 180; // seconds
};

// Factory function for creating platform-specific Bluetooth interface
std::unique_ptr<BluetoothInterface> createAppleBluetoothBridge();

} // namespace bitchat