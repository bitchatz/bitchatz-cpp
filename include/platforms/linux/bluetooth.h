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

    // GATT Service handling (public for static handler)
    DBusHandlerResult handleGattMessage(DBusConnection *conn, DBusMessage *msg);

private:
    // BLE Central (Scanner/Client) methods
    void scanThreadFunc();
    bool connectToDevice(const std::string &deviceAddress);
    void handleDeviceFound(const std::string &deviceAddress, const std::string &deviceName);
    bool startBLEScanning();
    bool stopBLEScanning();
    void processDiscoveredDevices();
    bool deviceAdvertisesService(const char *devicePath);
    std::string getDeviceAddress(const char *devicePath);
    std::string getDeviceName(const char *devicePath);
    std::string findDevicePath(const std::string &deviceAddress);

    // BLE Peripheral (Advertiser/Server) methods
    void advertiseThreadFunc();
    bool setupGattService();
    bool startAdvertising();
    void stopAdvertising();
    bool createGattCharacteristic();

    // GATT Service handling
    bool registerGattApplication();
    bool createGattApplicationObject();
    DBusHandlerResult handleGattGetProperty(DBusConnection *conn, DBusMessage *msg);
    DBusHandlerResult handleGattGetAllProperties(DBusConnection *conn, DBusMessage *msg);
    DBusHandlerResult handleGattGetManagedObjects(DBusConnection *conn, DBusMessage *msg);
    DBusHandlerResult handleGattReadValue(DBusConnection *conn, DBusMessage *msg);
    DBusHandlerResult handleGattWriteValue(DBusConnection *conn, DBusMessage *msg);
    DBusHandlerResult handleGattStartNotify(DBusConnection *conn, DBusMessage *msg);
    DBusHandlerResult handleGattStopNotify(DBusConnection *conn, DBusMessage *msg);
    void handleWriteRequest(const std::string &deviceAddress, const std::vector<uint8_t> &data);
    void handleReadRequest(const std::string &deviceAddress);
    void notifySubscribers(const std::vector<uint8_t> &data);
    bool writeCharacteristicValue(const std::string &deviceAddress, const std::vector<uint8_t> &data);
    std::string findCharacteristicPath(const std::string &devicePath);
    std::string getCharacteristicUUID(const char *charPath);

    // DBus communication
    bool initDbus();
    void cleanupDbus();
    bool findBluetoothAdapter();
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
    std::string gattApplicationPath;

    // Service UUIDs from constants
    static const std::string SERVICE_UUID;
    static const std::string CHARACTERISTIC_UUID;
};

} // namespace bitchat
