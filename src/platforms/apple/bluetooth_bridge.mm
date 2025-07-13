#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/protocol/packet_serializer.h"
#include "platforms/apple/bluetooth.h"
#include <memory>
#include <string>
#include <vector>

namespace bitchat
{

// ============================================================================
// C++ Bridge Layer - Implements BluetoothInterface and forwards to Objective-C
// ============================================================================

/**
 * @brief Bridge class that implements the C++ BluetoothInterface
 *
 * This class acts as a bridge between the C++ codebase and the Objective-C
 * Bluetooth implementation. It translates C++ calls to Objective-C method calls
 * and handles callback conversions between the two languages.
 */
class AppleBluetoothBridge : public BluetoothInterface
{
private:
    AppleBluetooth *impl;        // Objective-C implementation instance
    std::string localPeerId;     // Local device peer identifier
    PacketSerializer serializer; // Handles packet serialization/deserialization

    // Callback function pointers for C++ interface
    PeerDisconnectedCallback peerDisconnectedCallback; // Called when a peer disconnects
    PacketReceivedCallback packetReceivedCallback;     // Called when a packet is received

public:
    /**
     * @brief Constructor - Initializes the bridge and sets up callback translations
     */
    AppleBluetoothBridge()
        : impl(nil)
    {
        // Create the Objective-C Bluetooth implementation
        impl = [[AppleBluetooth alloc] init];
        if (impl)
        {
            // Set up callback bridges to translate Objective-C callbacks to C++

            // Bridge for peer disconnection events
            [impl setPeerDisconnectedCallback:^(NSString *peerId) {
                if (peerDisconnectedCallback)
                {
                    // Convert NSString to std::string for C++ callback
                    std::string cppPeerId = [peerId UTF8String];
                    peerDisconnectedCallback(cppPeerId);
                }
            }];

            // Bridge for packet reception events
            [impl setPacketReceivedCallback:^(NSData *packetData) {
                if (packetReceivedCallback)
                {
                    // Convert NSData to std::vector<uint8_t> for C++ processing
                    std::vector<uint8_t> data((uint8_t *)packetData.bytes,
                                              (uint8_t *)packetData.bytes + packetData.length);
                    // Deserialize the raw data into a BitchatPacket object
                    BitchatPacket packet = serializer.deserializePacket(data);
                    packetReceivedCallback(packet);
                }
            }];
        }
    }

    /**
     * @brief Destructor - Clean up Objective-C object
     */
    ~AppleBluetoothBridge()
    {
        if (impl)
        {
            [impl release]; // Release Objective-C object memory
        }
    }

    /**
     * @brief Initialize the Bluetooth system
     * @return true if initialization successful, false otherwise
     */
    bool initialize() override
    {
        if (!impl)
        {
            return false;
        }

        return [impl initialize]; // Forward to Objective-C implementation
    }

    /**
     * @brief Start Bluetooth scanning and advertising
     * @return true if started successfully, false otherwise
     */
    bool start() override
    {
        if (!impl)
        {
            return false;
        }

        return [impl start]; // Forward to Objective-C implementation
    }

    /**
     * @brief Stop Bluetooth operations
     */
    void stop() override
    {
        if (impl)
        {
            [impl stop]; // Forward to Objective-C implementation
        }
    }

    /**
     * @brief Send a packet to all connected peers
     * @param packet The packet to send
     * @return true if sent successfully, false otherwise
     */
    bool sendPacket(const BitchatPacket &packet) override
    {
        if (!impl)
        {
            return false;
        }

        // Serialize C++ packet to raw bytes
        std::vector<uint8_t> data = serializer.serializePacket(packet);
        // Convert to NSData for Objective-C
        NSData *nsData = [NSData dataWithBytes:data.data() length:data.size()];
        return [impl sendPacket:nsData]; // Forward to Objective-C implementation
    }

    /**
     * @brief Send a packet to a specific peer
     * @param packet The packet to send
     * @param peerId The target peer's identifier
     * @return true if sent successfully, false otherwise
     */
    bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerId) override
    {
        if (!impl)
        {
            return false;
        }

        // Serialize C++ packet to raw bytes
        std::vector<uint8_t> data = serializer.serializePacket(packet);
        // Convert to NSData for Objective-C
        NSData *nsData = [NSData dataWithBytes:data.data() length:data.size()];
        // Convert std::string to NSString for Objective-C
        NSString *nsPeerId = [NSString stringWithUTF8String:peerId.c_str()];
        return [impl sendPacket:nsData toPeer:nsPeerId]; // Forward to Objective-C implementation
    }

    /**
     * @brief Check if Bluetooth system is ready for operations
     * @return true if ready, false otherwise
     */
    bool isReady() const override
    {
        if (!impl)
        {
            return false;
        }

        return [impl isReady]; // Forward to Objective-C implementation
    }

    /**
     * @brief Get the local device's peer identifier
     * @return Local peer ID as string
     */
    std::string getLocalPeerId() const override
    {
        if (!impl)
        {
            return "";
        }

        // Get NSString from Objective-C and convert to std::string
        NSString *peerId = [impl getLocalPeerId];
        return peerId ? [peerId UTF8String] : "";
    }

    /**
     * @brief Set callback for peer disconnection events
     * @param callback Function to call when a peer disconnects
     */
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback) override
    {
        peerDisconnectedCallback = callback; // Store C++ callback function
    }

    /**
     * @brief Set callback for packet reception events
     * @param callback Function to call when a packet is received
     */
    void setPacketReceivedCallback(PacketReceivedCallback callback) override
    {
        packetReceivedCallback = callback; // Store C++ callback function
    }

    /**
     * @brief Get the number of currently connected peers
     * @return Number of connected peers
     */
    size_t getConnectedPeersCount() const override
    {
        if (!impl)
        {
            return 0;
        }

        return [impl getConnectedPeersCount]; // Forward to Objective-C implementation
    }
};

// ============================================================================
// Factory Function - Creates the C++ bridge instance
// ============================================================================

/**
 * @brief Factory function to create a Bluetooth interface instance
 *
 * This function is called by the BluetoothFactory to create a platform-specific
 * Bluetooth implementation. It returns a unique_ptr to ensure proper memory management.
 *
 * @return Unique pointer to the Bluetooth interface implementation
 */
std::unique_ptr<BluetoothInterface> createBluetoothInterface()
{
    return std::make_unique<AppleBluetoothBridge>();
}

} // namespace bitchat
