#include "platforms/apple/bluetooth_bridge.h"
#include "bitchat/protocol/packet_serializer.h"
#include "platforms/apple/bluetooth.h"
#include <string>
#include <vector>

namespace bitchat
{

// ============================================================================
// C++ Bridge Layer - Implements BluetoothInterface and forwards to Objective-C
// ============================================================================

AppleBluetoothBridge::AppleBluetoothBridge()
    : impl(nil), serializer(std::make_shared<PacketSerializer>())
{
    // Create the Objective-C Bluetooth implementation
    impl = [[AppleBluetooth alloc] init];

    if (impl)
    {
        // Set up callback bridges to translate Objective-C callbacks to C++

        // Bridge for peer connection events
        [impl setPeerConnectedCallback:^(NSString *peripheralID) {
            if (peerConnectedCallback)
            {
                std::string cppUUID = [peripheralID UTF8String];
                peerConnectedCallback(cppUUID);
            }
        }];

        // Bridge for peer disconnection events
        [impl setPeerDisconnectedCallback:^(NSString *peripheralID) {
            if (peerDisconnectedCallback)
            {
                // Convert NSString to std::string for C++ callback
                std::string cppUUID = [peripheralID UTF8String];
                peerDisconnectedCallback(cppUUID);
            }
        }];

        // Bridge for packet reception events
        [impl setPacketReceivedCallback:^(NSData *packetData, NSString *peripheralID) {
            if (packetReceivedCallback)
            {
                // Convert NSData to std::vector<uint8_t> for C++ processing
                std::vector<uint8_t> data((uint8_t *)packetData.bytes,
                                          (uint8_t *)packetData.bytes + packetData.length);

                // Deserialize the raw data into a BitchatPacket object
                BitchatPacket packet = serializer->deserializePacket(data);

                // Convert NSString to std::string for C++
                std::string cppUUID = peripheralID ? [peripheralID UTF8String] : "";

                packetReceivedCallback(packet, cppUUID);
            }
        }];
    }
}

AppleBluetoothBridge::~AppleBluetoothBridge()
{
    if (impl)
    {
        // Release Objective-C object memory
        [impl release];
    }
}

bool AppleBluetoothBridge::initialize()
{
    if (!impl)
    {
        return false;
    }

    // Forward to Objective-C implementation
    return [impl initialize];
}

bool AppleBluetoothBridge::start()
{
    if (!impl)
    {
        return false;
    }

    // Forward to Objective-C implementation
    return [impl start];
}

void AppleBluetoothBridge::stop()
{
    if (impl)
    {
        // Forward to Objective-C implementation
        [impl stop];
    }
}

bool AppleBluetoothBridge::sendPacket(const BitchatPacket &packet)
{
    if (!impl)
    {
        return false;
    }

    // Serialize C++ packet to raw bytes
    std::vector<uint8_t> data = serializer->serializePacket(packet);

    // Convert to NSData for Objective-C
    NSData *nsData = [NSData dataWithBytes:data.data() length:data.size()];

    // Forward to Objective-C implementation
    return [impl sendPacket:nsData];
}

bool AppleBluetoothBridge::sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID)
{
    if (!impl)
    {
        return false;
    }

    // Serialize C++ packet to raw bytes
    std::vector<uint8_t> data = serializer->serializePacket(packet);

    // Convert to NSData for Objective-C
    NSData *nsData = [NSData dataWithBytes:data.data() length:data.size()];

    // Convert std::string to NSString for Objective-C
    NSString *nsPeerID = [NSString stringWithUTF8String:peerID.c_str()];

    // Forward to Objective-C implementation
    return [impl sendPacket:nsData toPeer:nsPeerID];
}

bool AppleBluetoothBridge::isReady() const
{
    if (!impl)
    {
        return false;
    }

    // Forward to Objective-C implementation
    return [impl isReady];
}

std::string AppleBluetoothBridge::getLocalPeerID() const
{
    if (!impl)
    {
        return "";
    }

    // Get NSString from Objective-C and convert to std::string
    NSString *peerID = [impl getLocalPeerID];
    return peerID ? [peerID UTF8String] : "";
}

void AppleBluetoothBridge::setLocalPeerID(const std::string &peerID)
{
    if (!impl)
    {
        return;
    }

    // Convert std::string to NSString for Objective-C
    NSString *nsPeerID = [NSString stringWithUTF8String:peerID.c_str()];

    // Forward to Objective-C implementation
    [impl setLocalPeerID:nsPeerID];
}

void AppleBluetoothBridge::setPeerConnectedCallback(PeerConnectedCallback callback)
{
    // Store C++ callback function
    peerConnectedCallback = callback;
}

void AppleBluetoothBridge::setPeerDisconnectedCallback(PeerDisconnectedCallback callback)
{
    // Store C++ callback function
    peerDisconnectedCallback = callback;
}

void AppleBluetoothBridge::setPacketReceivedCallback(PacketReceivedCallback callback)
{
    // Store C++ callback function
    packetReceivedCallback = callback;
}

size_t AppleBluetoothBridge::getConnectedPeersCount() const
{
    if (!impl)
    {
        return 0;
    }

    // Forward to Objective-C implementation
    return [impl getConnectedPeersCount];
}

} // namespace bitchat
