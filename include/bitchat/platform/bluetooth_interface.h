#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace bitchat
{

// Forward declarations
struct BitchatPacket;
struct BitchatMessage;

// Callback types for Bluetooth transport events - PURE TRANSPORT ONLY
using PeerDisconnectedCallback = std::function<void(const std::string &peerId)>;
using PacketReceivedCallback = std::function<void(const BitchatPacket &packet)>;

// Abstract Bluetooth interface that platforms must implement - PURE TRANSPORT ONLY
// This interface handles only BLE transport, all business logic is in BitchatManager
class BluetoothInterface
{
public:
    virtual ~BluetoothInterface() = default;

    // Initialize Bluetooth subsystem
    virtual bool initialize() = 0;

    // Start advertising and scanning
    virtual bool start() = 0;

    // Stop all Bluetooth operations
    virtual void stop() = 0;

    // Send packet to all connected peers - PURE TRANSPORT
    virtual bool sendPacket(const BitchatPacket &packet) = 0;

    // Send packet to specific peer - PURE TRANSPORT
    virtual bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerId) = 0;

    // Check if Bluetooth is ready
    virtual bool isReady() const = 0;

    // Get local peer ID
    virtual std::string getLocalPeerId() const = 0;

    // Set callbacks - PURE TRANSPORT ONLY
    virtual void setPeerDisconnectedCallback(PeerDisconnectedCallback callback) = 0;
    virtual void setPacketReceivedCallback(PacketReceivedCallback callback) = 0;

    // Get connected peers count
    virtual size_t getConnectedPeersCount() const = 0;
};

} // namespace bitchat