#pragma once

#include "bitchat/core/bitchat_data.h"
#include "bitchat/platform/bluetooth_interface.h"
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
class IBluetoothNetwork;
class MessageService;

// NetworkService: Manages network operations, peer discovery, and message routing
class NetworkService
{
public:
    NetworkService();
    ~NetworkService();

    // Initialize the network service
    bool initialize(std::shared_ptr<IBluetoothNetwork> bluetoothNetworkInterface, std::shared_ptr<MessageService> messageService, std::shared_ptr<BluetoothAnnounceRunner> announceRunner, std::shared_ptr<CleanupRunner> cleanupRunner);

    // Start network operations
    bool start();

    // Stop network operations
    void stop();

    // Send a packet to the network
    bool sendPacket(const BitchatPacket &packet);

    // Send a packet to a specific peer
    bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID);

    // Set callbacks
    using PacketReceivedCallback = std::function<void(const BitchatPacket &, const std::string &)>;
    using PeerConnectedCallback = std::function<void(const std::string &)>;
    using PeerDisconnectedCallback = std::function<void(const std::string &)>;

    void setPacketReceivedCallback(PacketReceivedCallback callback);
    void setPeerConnectedCallback(PeerConnectedCallback callback);
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback);

private:
    // Bluetooth interface
    std::shared_ptr<IBluetoothNetwork> bluetoothNetworkInterface;

    // Message service for packet creation
    std::shared_ptr<MessageService> messageService;

    // Runners
    std::shared_ptr<BluetoothAnnounceRunner> announceRunner;
    std::shared_ptr<CleanupRunner> cleanupRunner;

    // Callbacks
    PacketReceivedCallback packetReceivedCallback;
    PeerConnectedCallback peerConnectedCallback;
    PeerDisconnectedCallback peerDisconnectedCallback;

    // Internal methods
    void onPeerConnected(const std::string &peripheralID);
    void onPeerDisconnected(const std::string &peripheralID);
    void onPacketReceived(const BitchatPacket &packet, const std::string &peripheralID);
    void onPeripheralDiscovered(const std::string &peripheralID);
    void relayPacket(const BitchatPacket &packet);
};

} // namespace bitchat
