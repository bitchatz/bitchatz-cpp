#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace bitchat
{

// Forward declarations
class BitchatPacket;
class BitchatMessage;

// Callback types for Bluetooth transport events
using PeerConnectedCallback = std::function<void(const std::string &peripheralID)>;
using PeerDisconnectedCallback = std::function<void(const std::string &peripheralID)>;
using PacketReceivedCallback = std::function<void(const BitchatPacket &packet, const std::string &peripheralID)>;

// Abstract Bluetooth network interface that platforms must implement
// This interface handles only BLE transport, all business logic is in BitchatManager
class IBluetoothNetwork
{
public:
    virtual ~IBluetoothNetwork() = default;

    // Initialize Bluetooth subsystem
    virtual bool initialize() = 0;

    // Start advertising and scanning
    virtual bool start() = 0;

    // Stop all Bluetooth operations
    virtual void stop() = 0;

    // Send packet to all connected peers
    virtual bool sendPacket(const BitchatPacket &packet) = 0;

    // Send packet to specific peer
    virtual bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID) = 0;

    // Check if Bluetooth is ready
    virtual bool isReady() const = 0;

    // Set callbacks
    virtual void setPeerConnectedCallback(PeerConnectedCallback callback) = 0;
    virtual void setPeerDisconnectedCallback(PeerDisconnectedCallback callback) = 0;
    virtual void setPacketReceivedCallback(PacketReceivedCallback callback) = 0;

    // Get connected peers count
    virtual size_t getConnectedPeersCount() const = 0;
};

} // namespace bitchat
