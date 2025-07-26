#pragma once

#include "bitchat/platform/bluetooth_interface.h"
#include <atomic>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bitchat
{

class DummyBluetoothNetwork : public IBluetoothNetwork
{
public:
    DummyBluetoothNetwork();
    ~DummyBluetoothNetwork() override = default;

    bool initialize() override;
    bool start() override;
    void stop() override;
    bool sendPacket(const BitchatPacket &packet) override;
    bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID) override;
    bool isReady() const override;

    void setPeerConnectedCallback(PeerConnectedCallback callback) override;
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback) override;
    void setPacketReceivedCallback(PacketReceivedCallback callback) override;
    size_t getConnectedPeersCount() const override;
};

} // namespace bitchat
