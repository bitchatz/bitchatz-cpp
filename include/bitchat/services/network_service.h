#pragma once

#include "bitchat/protocol/packet.h"
#include <atomic>
#include <functional>
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
class BluetoothAnnounceRunner;
class CleanupRunner;
class BluetoothInterface;

// NetworkService: Manages network operations, peer discovery, and message routing
class NetworkService
{
public:
    NetworkService();
    ~NetworkService();

    // Initialize the network service
    bool initialize(std::shared_ptr<BluetoothInterface> bluetooth);

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

    // Get peers
    std::vector<BitchatPeer> getPeers() const;

    // Get peers count
    size_t getPeersCount() const;

    // Check if a peer is online
    bool isPeerOnline(const std::string &peerID) const;

    // Get peer information
    std::optional<BitchatPeer> getPeerInfo(const std::string &peerID) const;

    // Update peer information
    void updatePeerInfo(const std::string &peerID, const BitchatPeer &peer);

    // Remove stale peers
    void cleanupStalePeers(time_t timeout = 180);

    // Set callbacks
    using PacketReceivedCallback = std::function<void(const BitchatPacket &, const std::string &)>;
    using PeerConnectedCallback = std::function<void(const std::string &)>;
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

    // Set runner instances
    void setAnnounceRunner(std::shared_ptr<BluetoothAnnounceRunner> runner);
    void setCleanupRunner(std::shared_ptr<CleanupRunner> runner);

private:
    // Bluetooth interface
    std::shared_ptr<BluetoothInterface> bluetoothInterface;

    // Network state
    std::vector<BitchatPeer> peers;
    std::set<std::string> processedMessages;
    std::string localPeerID;
    std::string nickname;

    // Runners
    std::shared_ptr<BluetoothAnnounceRunner> announceRunner;
    std::shared_ptr<CleanupRunner> cleanupRunner;

    // Threading
    std::atomic<bool> shouldExit;

    // Mutexes
    mutable std::mutex peersMutex;
    mutable std::mutex processedMutex;

    // Callbacks
    PacketReceivedCallback packetReceivedCallback;
    PeerConnectedCallback peerConnectedCallback;
    PeerDisconnectedCallback peerDisconnectedCallback;

    // Internal methods
    void onPeerConnected(const std::string &peripheralID);
    void onPeerDisconnected(const std::string &peripheralID);
    void onPacketReceived(const BitchatPacket &packet, const std::string &peripheralID);
    void processPacket(const BitchatPacket &packet, const std::string &peripheralID);
    void processAnnouncePacket(const BitchatPacket &packet, const std::string &peripheralID);
    void relayPacket(const BitchatPacket &packet);
    bool wasMessageProcessed(const std::string &messageID);
    void markMessageProcessed(const std::string &messageID);

    // Constants
    static constexpr int PEER_TIMEOUT = 180; // seconds
};

} // namespace bitchat
