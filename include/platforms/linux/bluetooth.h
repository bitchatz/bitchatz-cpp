#pragma once

#include "bitchat/platform/bluetooth_interface.h"
#include <atomic>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <dbus/dbus.h>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace bitchat
{

class LinuxBluetooth : public BluetoothInterface
{
public:
    LinuxBluetooth();
    ~LinuxBluetooth() override;

    bool initialize() override;
    bool start() override;
    void stop() override;
    bool sendPacket(const BitchatPacket &packet) override;
    bool sendPacketToPeer(const BitchatPacket &packet, const std::string &peerId) override;
    bool isReady() const override;
    std::string getLocalPeerId() const override;
    void setPeerDisconnectedCallback(PeerDisconnectedCallback callback) override;
    void setPacketReceivedCallback(PacketReceivedCallback callback) override;
    size_t getConnectedPeersCount() const override;

private:
    // BLE Central (Scanner/Client) methods
    void scanThreadFunc();
    void connectToDevice(const std::string &deviceAddress);
    void handleDeviceFound(const std::string &deviceAddress, const std::string &deviceName);

    // BLE Peripheral (Advertiser/Server) methods
    void advertiseThreadFunc();
    void setupGattService();
    void startAdvertising();
    void stopAdvertising();

    // GATT Service handling
    void handleWriteRequest(const std::string &deviceAddress, const std::vector<uint8_t> &data);
    void handleReadRequest(const std::string &deviceAddress);
    void notifySubscribers(const std::vector<uint8_t> &data);

    // DBus communication
    bool initDbus();
    void cleanupDbus();
    bool sendDbusMessage(const std::string &path, const std::string &interface,
                         const std::string &method, DBusMessageIter *args = nullptr);
    bool getDbusProperty(const std::string &path, const std::string &interface,
                         const std::string &property, DBusMessageIter *value);

    // Utility methods
    std::string generateLocalPeerId();
    void processReceivedData(const std::string &deviceAddress, const std::vector<uint8_t> &data);

    // BLE state
    std::atomic<bool> ready;
    std::atomic<bool> stopThreads;
    std::string localPeerId;

    // DBus connection
    DBusConnection *dbusConn;

    // HCI socket for Bluetooth operations
    int hciSocket;
    int deviceId;

    // Threads
    std::thread scanThread;
    std::thread advertiseThread;

    // Callbacks
    PacketReceivedCallback packetReceivedCallback;
    PeerDisconnectedCallback peerDisconnectedCallback;

    // Connected devices management
    std::map<std::string, std::string> connectedDevices; // address -> peerId
    std::map<std::string, std::string> deviceNames;      // address -> name
    std::vector<std::string> subscribedDevices;          // devices subscribed to our characteristic
    mutable std::mutex devicesMutex;

    // GATT service paths
    std::string adapterPath;
    std::string servicePath;
    std::string characteristicPath;

    // Service UUIDs from constants
    static const std::string SERVICE_UUID;
    static const std::string CHARACTERISTIC_UUID;
};

} // namespace bitchat
