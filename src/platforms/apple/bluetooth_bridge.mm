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
    : impl(nil), serializer(std::make_unique<PacketSerializer>())
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
                BitchatPacket packet = serializer->deserializePacket(data);
                packetReceivedCallback(packet);
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

bool AppleBluetoothBridge::sendPacketToPeer(const BitchatPacket &packet, const std::string &peerId)
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
    NSString *nsPeerId = [NSString stringWithUTF8String:peerId.c_str()];

    // Forward to Objective-C implementation
    return [impl sendPacket:nsData toPeer:nsPeerId];
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

std::string AppleBluetoothBridge::getLocalPeerId() const
{
    if (!impl)
    {
        return "";
    }

    // Get NSString from Objective-C and convert to std::string
    NSString *peerId = [impl getLocalPeerId];
    return peerId ? [peerId UTF8String] : "";
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
