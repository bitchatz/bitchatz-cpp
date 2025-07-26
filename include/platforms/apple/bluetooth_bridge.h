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
 * @brief Bridge class that implements the C++ IBluetoothNetwork
 *
 * This class acts as a bridge between the C++ codebase and the Objective-C
 * Bluetooth implementation. It translates C++ calls to Objective-C method calls
 * and handles callback conversions between the two languages.
 */
class AppleBluetoothNetworkBridge : public bitchat::IBluetoothNetwork
{
private:
    AppleBluetooth *impl;                                  // Objective-C implementation instance
    std::shared_ptr<bitchat::PacketSerializer> serializer; // Handles packet serialization/deserialization

    // Callback function pointers for C++ interface
    PeerConnectedCallback peerConnectedCallback;               // Called when a peer connects
    PeerDisconnectedCallback peerDisconnectedCallback;         // Called when a peer disconnects
    PacketReceivedCallback packetReceivedCallback;             // Called when a packet is received
    PeripheralDiscoveredCallback peripheralDiscoveredCallback; // Called when peripheral is discovered

public:
    /**
     * @brief Constructor - Initializes the bridge and sets up callback translations
     */
    AppleBluetoothNetworkBridge();

    /**
     * @brief Destructor - Clean up Objective-C object
     */
    ~AppleBluetoothNetworkBridge();

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
     * @param peerID The target peer's identifier
     * @return true if sent successfully, false otherwise
     */
    bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID) override;

    /**
     * @brief Check if Bluetooth system is ready for operations
     * @return true if ready, false otherwise
     */
    bool isReady() const override;

    /**
     * @brief Set callback for peer connection events
     * @param callback Function to call when a peer connects
     */
    void setPeerConnectedCallback(PeerConnectedCallback callback) override;

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
     * @brief Set callback for peripheral discovery events
     * @param callback Function to call when peripheral is discovered
     */
    void setPeripheralDiscoveredCallback(PeripheralDiscoveredCallback callback) override;

    /**
     * @brief Get the number of currently connected peers
     * @return Number of connected peers
     */
    size_t getConnectedPeersCount() const override;
};

} // namespace bitchat
