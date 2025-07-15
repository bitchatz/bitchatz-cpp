#pragma once

#include "bitchat/platform/bluetooth_interface.h"
#include <functional>
#include <memory>
#include <string>
#include <vector>

// Forward declarations
class ChatClient;

class LinuxBluetooth : public bitchat::BluetoothInterface
{
public:
    LinuxBluetooth();
    ~LinuxBluetooth();

    bool initialize() override;
    bool start() override;
    void stop() override;

    bool sendPacket(const bitchat::BitchatPacket &packet) override;
    bool sendPacketToPeer(const bitchat::BitchatPacket &packet, const std::string &peerId) override;

    bool isReady() const override;
    std::string getLocalPeerId() const override;
    size_t getConnectedPeersCount() const override;

    // Advertisement status methods
    bool isAdvertising() const;
    std::string getAdvertisementStatus() const;

    void setPeerDisconnectedCallback(bitchat::PeerDisconnectedCallback callback) override;
    void setPacketReceivedCallback(bitchat::PacketReceivedCallback callback) override;

    // Method to handle data received from other devices
    void onDataReceived(const std::vector<uint8_t> &data);

    // Methods for managing subscribed clients (used by ChatCharacteristic)
    void addSubscribedClient(std::shared_ptr<ChatClient> client);
    void removeSubscribedClient(std::shared_ptr<ChatClient> client);

private:
    void startScanning();
    void registerAdvertisement();
    void setupDeviceMonitoring();
    void onDeviceRemoved(const std::string &devicePath);
    void cleanupDisconnectedDevices();
    struct Impl;
    std::unique_ptr<Impl> impl;
};
