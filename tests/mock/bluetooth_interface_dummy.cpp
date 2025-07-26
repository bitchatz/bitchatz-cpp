#include "mock/bluetooth_interface_dummy.h"

namespace bitchat
{

DummyBluetoothNetwork::DummyBluetoothNetwork()
{
    // Pass
}

bool DummyBluetoothNetwork::initialize()
{
    return true;
}

bool DummyBluetoothNetwork::start()
{
    return true;
}

void DummyBluetoothNetwork::stop()
{
    // Pass
}

bool DummyBluetoothNetwork::sendPacket([[maybe_unused]] const BitchatPacket &packet)
{
    return true;
}

bool DummyBluetoothNetwork::sendPacketToPeer([[maybe_unused]] const BitchatPacket &packet, [[maybe_unused]] const std::string &peerID)
{
    return true;
}

bool DummyBluetoothNetwork::isReady() const
{
    return true;
}

void DummyBluetoothNetwork::setPeerConnectedCallback([[maybe_unused]] PeerConnectedCallback callback)
{
    // Pass
}

void DummyBluetoothNetwork::setPeerDisconnectedCallback([[maybe_unused]] PeerDisconnectedCallback callback)
{
    // Pass
}

void DummyBluetoothNetwork::setPacketReceivedCallback([[maybe_unused]] PacketReceivedCallback callback)
{
    // Pass
}

size_t DummyBluetoothNetwork::getConnectedPeersCount() const
{
    return 0;
}

} // namespace bitchat
