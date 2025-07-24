#pragma once

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/protocol/packet.h"

namespace bitchat
{
namespace testing
{

class MockBluetoothInterface : public BluetoothInterface
{
public:
    MOCK_METHOD(bool, initialize, (), (override));
    MOCK_METHOD(bool, start, (), (override));
    MOCK_METHOD(void, stop, (), (override));
    MOCK_METHOD(bool, sendPacket, (const BitchatPacket &packet), (override));
    MOCK_METHOD(bool, sendPacketToPeer, (const BitchatPacket &packet, const std::string &peerID), (override));
    MOCK_METHOD(bool, isReady, (), (const, override));
    MOCK_METHOD(std::string, getLocalPeerID, (), (const, override));
    MOCK_METHOD(void, setLocalPeerID, (const std::string &peerID), (override));
    MOCK_METHOD(void, setPeerConnectedCallback, (PeerConnectedCallback callback), (override));
    MOCK_METHOD(void, setPeerDisconnectedCallback, (PeerDisconnectedCallback callback), (override));
    MOCK_METHOD(void, setPacketReceivedCallback, (PacketReceivedCallback callback), (override));
    MOCK_METHOD(size_t, getConnectedPeersCount, (), (const, override));
};

} // namespace testing
} // namespace bitchat
