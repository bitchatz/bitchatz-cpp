#pragma once

#include "bitchat/core/constants.h"
#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/protocol/packet_serializer.h"

#include <bluez/Adapter.h>
#include <bluez/Central.h>
#include <bluez/GattCharacteristic.h>
#include <bluez/GattService.h>
#include <bluez/Peripheral.h>

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <string>
#include <vector>

namespace bitchat
{

class LinuxBluetooth : public BluetoothInterface
{
public:
    using PeerDisconnectedCallback = std::function<void(const std::string &)>;
    using PacketReceivedCallback = std::function<void(const BitchatPacket &)>;

    LinuxBluetooth();
    ~LinuxBluetooth();

    bool initialize() override;
    bool start() override;
    void stop() override;

    void setPeerDisconnectedCallback(PeerDisconnectedCallback cb) override;
    void setPacketReceivedCallback(PacketReceivedCallback cb) override;

    bool sendPacket(const BitchatPacket &packet) override;
    bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerId) override;

    bool isReady() const override;
    std::string getLocalPeerId() const override;
    size_t getConnectedPeersCount() const override;

private:
    // BLE objects
    std::shared_ptr<bluez::Adapter> adapter;
    std::shared_ptr<bluez::Peripheral> peripheral;
    std::shared_ptr<bluez::Central> central;
    std::shared_ptr<bluez::GattService> service;
    std::shared_ptr<bluez::GattCharacteristic> characteristic;

    // Peer tracking
    std::map<std::string, std::shared_ptr<bluez::Peripheral>> connectedPeripherals;
    std::map<std::string, std::shared_ptr<bluez::GattCharacteristic>> peripheralCharacteristics;
    std::vector<std::string> subscribedCentrals;

    // Callbacks
    PeerDisconnectedCallback peerDisconnectedCallback;
    PacketReceivedCallback packetReceivedCallback;

    // State
    bool ready;
    std::string localPeerId;
    mutable std::mutex mutex;

    PacketSerializer serializer;

    // Internals
    void setupPeripheral();
    void setupCentral();

    static std::string generatePeerId();
};

} // namespace bitchat
