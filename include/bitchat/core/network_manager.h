#pragma once

#include "bitchat/protocol/packet.h"
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace bitchat
{

// Forward declarations
class BluetoothInterface;

// NetworkManager: manages network operations, peer discovery, and message routing
class NetworkManager
{
public:
    NetworkManager();
    ~NetworkManager();

    // Initialize the network manager
    bool initialize(std::unique_ptr<BluetoothInterface> bluetooth);

    // Set local peer ID
    void setLocalPeerID(const std::string &peerID);

    // Start network operations
    bool start();

    // Stop network operations
    void stop();

    // Send a packet to the network
    bool sendPacket(const BitchatPacket &packet);

    // Send a packet to a specific peer
    bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID);

    // Get online peers
    std::map<std::string, BitchatPeer> getOnlinePeers() const;

    // Get connected peers count
    size_t getConnectedPeersCount() const;

    // Check if a peer is online
    bool isPeerOnline(const std::string &peerID) const;

    // Get peer information
    std::optional<BitchatPeer> getPeerInfo(const std::string &peerID) const;

    // Update peer information
    void updatePeerInfo(const std::string &peerID, const BitchatPeer &peer);

    // Remove stale peers
    void cleanupStalePeers(time_t timeout = 180);

    // Set callbacks
    using PacketReceivedCallback = std::function<void(const BitchatPacket &)>;
    using PeerConnectedCallback = std::function<void(const std::string &, const std::string &)>;
    using PeerDisconnectedCallback = std::function<void(const std::string &, const std::string &)>;

    void setPacketReceivedCallback(PacketReceivedCallback callback);
    void setPeerConnectedCallback(PeerConnectedCallback callback);
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback);

    // Get local peer ID
    std::string getLocalPeerID() const;

    // Check if network is ready
    bool isReady() const;

    // Set nickname for announce packets
    void setNickname(const std::string &nickname);

private:
    // Bluetooth interface
    std::unique_ptr<BluetoothInterface> bluetoothInterface;

    // Network state
    std::map<std::string, BitchatPeer> onlinePeers;
    std::set<std::string> processedMessages;
    std::string localPeerID;
    std::string nickname;

    // Threading
    std::atomic<bool> shouldExit;
    std::thread announceThread;
    std::thread cleanupThread;

    // Mutexes
    mutable std::mutex peersMutex;
    mutable std::mutex processedMutex;

    // Callbacks
    PacketReceivedCallback packetReceivedCallback;
    PeerConnectedCallback peerConnectedCallback;
    PeerDisconnectedCallback peerDisconnectedCallback;

    // Internal methods
    void announceLoop();
    void cleanupLoop();
    void onPeerConnected(const std::string &peerID, const std::string &nickname);
    void onPeerDisconnected(const std::string &peerID);
    void onPacketReceived(const BitchatPacket &packet);
    void processPacket(const BitchatPacket &packet);
    void processAnnouncePacket(const BitchatPacket &packet);
    void relayPacket(const BitchatPacket &packet);
    bool wasMessageProcessed(const std::string &messageID);
    void markMessageProcessed(const std::string &messageID);

    // Constants
    static constexpr int ANNOUNCE_INTERVAL = 15; // seconds
    static constexpr int CLEANUP_INTERVAL = 30;  // seconds
    static constexpr int PEER_TIMEOUT = 180;     // seconds
};

} // namespace bitchat
