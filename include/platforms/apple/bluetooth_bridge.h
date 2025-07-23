#pragma once

#include "bitchat/platform/bluetooth_interface.h"
#include <memory>
#include <string>

// Forward declarations to avoid including headers in C++ headers
#ifdef __OBJC__
@class AppleBluetooth;
#else
typedef struct objc_object AppleBluetooth;
#endif

// Forward declaration for PacketSerializer
namespace bitchat
{
class PacketSerializer;
}

namespace bitchat
{

/**
 * @brief Bridge class that implements the C++ BluetoothInterface
 *
 * This class acts as a bridge between the C++ codebase and the Objective-C
 * Bluetooth implementation. It translates C++ calls to Objective-C method calls
 * and handles callback conversions between the two languages.
 */
class AppleBluetoothBridge : public bitchat::BluetoothInterface
{
private:
    AppleBluetooth *impl;                                  // Objective-C implementation instance
    std::string localPeerId;                               // Local device peer identifier
    std::unique_ptr<bitchat::PacketSerializer> serializer; // Handles packet serialization/deserialization

    // Callback function pointers for C++ interface
    PeerDisconnectedCallback peerDisconnectedCallback; // Called when a peer disconnects
    PacketReceivedCallback packetReceivedCallback;     // Called when a packet is received

public:
    /**
     * @brief Constructor - Initializes the bridge and sets up callback translations
     */
    AppleBluetoothBridge();

    /**
     * @brief Destructor - Clean up Objective-C object
     */
    ~AppleBluetoothBridge();

    /**
     * @brief Initialize the Bluetooth system
     * @return true if initialization successful, false otherwise
     */
    bool initialize() override;

    /**
     * @brief Start Bluetooth scanning and advertising
     * @return true if started successfully, false otherwise
     */
    bool start() override;

    /**
     * @brief Stop Bluetooth operations
     */
    void stop() override;

    /**
     * @brief Send a packet to all connected peers
     * @param packet The packet to send
     * @return true if sent successfully, false otherwise
     */
    bool sendPacket(const BitchatPacket &packet) override;

    /**
     * @brief Send a packet to a specific peer
     * @param packet The packet to send
     * @param peerId The target peer's identifier
     * @return true if sent successfully, false otherwise
     */
    bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerId) override;

    /**
     * @brief Check if Bluetooth system is ready for operations
     * @return true if ready, false otherwise
     */
    bool isReady() const override;

    /**
     * @brief Get the local device's peer identifier
     * @return Local peer ID as string
     */
    std::string getLocalPeerId() const override;

    /**
     * @brief Set the local device's peer identifier
     * @param peerId The peer ID to set
     */
    void setLocalPeerId(const std::string &peerId) override;

    /**
     * @brief Set callback for peer disconnection events
     * @param callback Function to call when a peer disconnects
     */
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback) override;

    /**
     * @brief Set callback for packet reception events
     * @param callback Function to call when a packet is received
     */
    void setPacketReceivedCallback(PacketReceivedCallback callback) override;

    /**
     * @brief Get the number of currently connected peers
     * @return Number of connected peers
     */
    size_t getConnectedPeersCount() const override;
};

} // namespace bitchat
