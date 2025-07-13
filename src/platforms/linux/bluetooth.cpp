#include "platforms/linux/bluetooth.h"
#include "bitchat/core/constants.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/protocol/packet_serializer.h"
#include <algorithm>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <chrono>
#include <cstring>
#include <future>
#include <iomanip>
#include <iostream>
#include <random>
#include <spdlog/spdlog.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace bitchat
{

// Static member initialization
const std::string LinuxBluetooth::SERVICE_UUID = constants::BLE_SERVICE_UUID;
const std::string LinuxBluetooth::CHARACTERISTIC_UUID = constants::BLE_CHARACTERISTIC_UUID;

LinuxBluetooth::LinuxBluetooth()
    : ready(false)
    , stopThreads(false)
    , dbusConn(nullptr)
    , hciSocket(-1)
    , deviceId(-1)
    , adapterPath("")
    , servicePath("")
    , characteristicPath("")
{
    // Generate local peer ID
    localPeerId = generateLocalPeerId();
    spdlog::info("Local peer ID generated: {}", localPeerId);

    // Initialize HCI socket
    deviceId = hci_get_route(nullptr);
    if (deviceId < 0)
    {
        spdlog::error("No Bluetooth adapter found");
        throw std::runtime_error("No Bluetooth adapter found");
    }

    hciSocket = hci_open_dev(deviceId);
    if (hciSocket < 0)
    {
        spdlog::error("Failed to open HCI socket");
        throw std::runtime_error("Failed to open HCI socket");
    }

    spdlog::info("HCI socket opened successfully");
}

LinuxBluetooth::~LinuxBluetooth()
{
    stop();

    if (hciSocket >= 0)
    {
        close(hciSocket);
        spdlog::info("Closed HCI socket.");
    }

    cleanupDbus();
}

bool LinuxBluetooth::initialize()
{
    if (!initDbus())
    {
        spdlog::error("Failed to initialize DBus connection");
        return false;
    }

    // Find the Bluetooth adapter
    if (!findBluetoothAdapter())
    {
        spdlog::error("Failed to find Bluetooth adapter");
        return false;
    }

    // Set up GATT service
    if (!setupGattService())
    {
        spdlog::error("Failed to setup GATT service");
        return false;
    }

    ready = true;
    spdlog::info("LinuxBluetooth BLE initialized successfully.");
    return true;
}

bool LinuxBluetooth::start()
{
    if (!ready)
    {
        spdlog::error("Bluetooth not ready, cannot start");
        return false;
    }

    stopThreads = false;

    // Start scanning thread (Central role)
    scanThread = std::thread(&LinuxBluetooth::scanThreadFunc, this);

    // Start advertising thread (Peripheral role)
    advertiseThread = std::thread(&LinuxBluetooth::advertiseThreadFunc, this);

    spdlog::info("Bluetooth BLE scanning and advertising threads started.");
    return true;
}

void LinuxBluetooth::stop()
{
    stopThreads = true;
    spdlog::info("Stopping Bluetooth BLE threads...");

    if (scanThread.joinable())
    {
        scanThread.join();
    }

    if (advertiseThread.joinable())
    {
        advertiseThread.join();
    }

    stopAdvertising();

    // Clear connected devices
    std::lock_guard<std::mutex> lock(devicesMutex);
    connectedDevices.clear();
    deviceNames.clear();
    subscribedDevices.clear();

    spdlog::info("Bluetooth BLE threads stopped.");
}

bool LinuxBluetooth::sendPacket(const BitchatPacket &packet)
{
    if (!ready)
    {
        spdlog::warn("Bluetooth not ready, cannot send packet");
        return false;
    }

    PacketSerializer serializer;
    std::vector<uint8_t> data = serializer.serializePacket(packet);

    std::lock_guard<std::mutex> lock(devicesMutex);

    if (connectedDevices.empty() && subscribedDevices.empty())
    {
        spdlog::warn("No connected peers to send packet to.");
        return false;
    }

    bool sentToAny = false;

    // Send to connected devices (devices we're connected to)
    for (const auto &[address, peerId] : connectedDevices)
    {
        if (sendPacketToPeer(packet, peerId))
        {
            sentToAny = true;
        }
    }

    // Send to subscribed devices (devices connected to us)
    if (!subscribedDevices.empty())
    {
        notifySubscribers(data);
        sentToAny = true;
    }

    return sentToAny;
}

bool LinuxBluetooth::sendPacketToPeer(const BitchatPacket &packet, const std::string &peerId)
{
    if (!ready)
    {
        return false;
    }

    PacketSerializer serializer;
    std::vector<uint8_t> data = serializer.serializePacket(packet);

    std::lock_guard<std::mutex> lock(devicesMutex);

    // Find device address by peer ID
    for (const auto &[address, connectedPeerId] : connectedDevices)
    {
        if (connectedPeerId == peerId)
        {
            // Send via GATT characteristic write
            return writeCharacteristicValue(address, data);
        }
    }

    spdlog::warn("Peer {} not found in connected devices.", peerId);
    return false;
}

bool LinuxBluetooth::isReady() const
{
    return ready && hciSocket >= 0;
}

std::string LinuxBluetooth::getLocalPeerId() const
{
    return localPeerId;
}

void LinuxBluetooth::setPeerDisconnectedCallback(PeerDisconnectedCallback callback)
{
    peerDisconnectedCallback = callback;
}

void LinuxBluetooth::setPacketReceivedCallback(PacketReceivedCallback callback)
{
    packetReceivedCallback = callback;
}

size_t LinuxBluetooth::getConnectedPeersCount() const
{
    std::lock_guard<std::mutex> lock(devicesMutex);
    return connectedDevices.size();
}

void LinuxBluetooth::scanThreadFunc()
{
    spdlog::info("BLE scan thread started.");

    while (!stopThreads)
    {
        // Start BLE scanning using BlueZ DBus API
        if (!startBLEScanning())
        {
            spdlog::error("Failed to start BLE scanning");
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        // Scan for 10 seconds
        std::this_thread::sleep_for(std::chrono::seconds(10));

        // Stop scanning
        stopBLEScanning();

        // Process discovered devices
        processDiscoveredDevices();
    }

    spdlog::info("BLE scan thread stopped.");
}

void LinuxBluetooth::advertiseThreadFunc()
{
    spdlog::info("BLE advertising thread started.");

    while (!stopThreads)
    {
        // Start advertising our service
        if (!startAdvertising())
        {
            spdlog::error("Failed to start BLE advertising");
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }

        // Keep advertising until stopped
        while (!stopThreads)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    stopAdvertising();
    spdlog::info("BLE advertising thread stopped.");
}

bool LinuxBluetooth::initDbus()
{
    dbus_error_t error;
    dbus_error_init(&error);

    dbusConn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
    if (dbus_error_is_set(&error))
    {
        spdlog::error("Failed to connect to DBus: {}", error.message);
        dbus_error_free(&error);
        return false;
    }

    // Request name for our service
    int result = dbus_bus_request_name(dbusConn, "org.bitchat.ble",
                                       DBUS_NAME_FLAG_REPLACE_EXISTING, &error);
    if (dbus_error_is_set(&error))
    {
        spdlog::error("Failed to request DBus name: {}", error.message);
        dbus_error_free(&error);
        return false;
    }

    spdlog::info("DBus connection established");
    return true;
}

void LinuxBluetooth::cleanupDbus()
{
    if (dbusConn)
    {
        dbus_connection_unref(dbusConn);
        dbusConn = nullptr;
        spdlog::info("DBus connection closed");
    }
}

bool LinuxBluetooth::findBluetoothAdapter()
{
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    if (!msg)
    {
        return false;
    }

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return false;
    }

    DBusMessageIter iter;
    if (dbus_message_iter_init(reply, &iter))
    {
        DBusMessageIter dict;
        dbus_message_iter_recurse(&iter, &dict);

        do
        {
            DBusMessageIter entry;
            dbus_message_iter_recurse(&dict, &entry);

            DBusMessageIter key;
            dbus_message_iter_recurse(&entry, &key);
            const char *path;
            dbus_message_iter_get_arg(&key, &path);

            // Check if this is a Bluetooth adapter
            if (strstr(path, "/org/bluez/hci") != nullptr)
            {
                adapterPath = path;
                spdlog::info("Found Bluetooth adapter: {}", adapterPath);
                dbus_message_unref(reply);
                return true;
            }
        } while (dbus_message_iter_next(&dict));
    }

    dbus_message_unref(reply);
    return false;
}

bool LinuxBluetooth::setupGattService()
{
    // Create GATT service using BlueZ DBus API
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", adapterPath.c_str(), "org.bluez.GattManager1", "RegisterApplication");
    if (!msg)
    {
        return false;
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);

    // Service path
    servicePath = adapterPath + "/service0";
    const char *servicePathStr = servicePath.c_str();
    dbus_message_iter_append_arg(&iter, DBUS_TYPE_OBJECT_PATH, &servicePathStr);

    // Empty options dictionary
    DBusMessageIter options;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &options);
    dbus_message_iter_close_container(&iter, &options);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return false;
    }

    dbus_message_unref(reply);

    // Create characteristic
    characteristicPath = servicePath + "/char0";
    if (!createGattCharacteristic())
    {
        return false;
    }

    spdlog::info("GATT service setup complete: {}", servicePath);
    return true;
}

bool LinuxBluetooth::createGattCharacteristic()
{
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", servicePath.c_str(), "org.freedesktop.DBus.Properties", "Set");
    if (!msg)
    {
        return false;
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);

    const char *interface = "org.bluez.GattCharacteristic1";
    const char *property = "UUID";
    const char *uuid = CHARACTERISTIC_UUID.c_str();

    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &property);

    DBusMessageIter variant;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, "s", &variant);
    dbus_message_iter_append_arg(&variant, DBUS_TYPE_STRING, &uuid);
    dbus_message_iter_close_container(&iter, &variant);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return false;
    }

    dbus_message_unref(reply);
    spdlog::info("GATT characteristic created: {}", characteristicPath);
    return true;
}

bool LinuxBluetooth::startBLEScanning()
{
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", adapterPath.c_str(), "org.bluez.Adapter1", "StartDiscovery");
    if (!msg)
    {
        return false;
    }

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return false;
    }

    dbus_message_unref(reply);
    spdlog::debug("BLE scanning started");
    return true;
}

bool LinuxBluetooth::stopBLEScanning()
{
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", adapterPath.c_str(), "org.bluez.Adapter1", "StopDiscovery");
    if (!msg)
    {
        return false;
    }

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return false;
    }

    dbus_message_unref(reply);
    spdlog::debug("BLE scanning stopped");
    return true;
}

void LinuxBluetooth::processDiscoveredDevices()
{
    // Get discovered devices from BlueZ
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", adapterPath.c_str(), "org.freedesktop.DBus.Properties", "Get");
    if (!msg)
    {
        return;
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);

    const char *interface = "org.bluez.Adapter1";
    const char *property = "Devices";

    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &property);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return;
    }

    DBusMessageIter replyIter;
    if (dbus_message_iter_init(reply, &replyIter))
    {
        DBusMessageIter variant;
        dbus_message_iter_recurse(&replyIter, &variant);

        DBusMessageIter array;
        dbus_message_iter_recurse(&variant, &array);

        do
        {
            DBusMessageIter devicePath;
            dbus_message_iter_recurse(&array, &devicePath);
            const char *path;
            dbus_message_iter_get_arg(&devicePath, &path);

            // Check if device advertises our service
            if (deviceAdvertisesService(path))
            {
                std::string deviceAddress = getDeviceAddress(path);
                std::string deviceName = getDeviceName(path);

                if (!deviceAddress.empty())
                {
                    handleDeviceFound(deviceAddress, deviceName);
                }
            }
        } while (dbus_message_iter_next(&array));
    }

    dbus_message_unref(reply);
}

bool LinuxBluetooth::deviceAdvertisesService(const char *devicePath)
{
    // Check if device advertises our service UUID
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", devicePath, "org.freedesktop.DBus.Properties", "Get");
    if (!msg)
    {
        return false;
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);

    const char *interface = "org.bluez.Device1";
    const char *property = "UUIDs";

    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &property);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return false;
    }

    DBusMessageIter replyIter;
    if (dbus_message_iter_init(reply, &replyIter))
    {
        DBusMessageIter variant;
        dbus_message_iter_recurse(&replyIter, &variant);

        DBusMessageIter array;
        dbus_message_iter_recurse(&variant, &array);

        do
        {
            const char *uuid;
            dbus_message_iter_get_arg(&array, &uuid);

            if (strcmp(uuid, SERVICE_UUID.c_str()) == 0)
            {
                dbus_message_unref(reply);
                return true;
            }
        } while (dbus_message_iter_next(&array));
    }

    dbus_message_unref(reply);
    return false;
}

std::string LinuxBluetooth::getDeviceAddress(const char *devicePath)
{
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", devicePath, "org.freedesktop.DBus.Properties", "Get");
    if (!msg)
    {
        return "";
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);

    const char *interface = "org.bluez.Device1";
    const char *property = "Address";

    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &property);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return "";
    }

    DBusMessageIter replyIter;
    if (dbus_message_iter_init(reply, &replyIter))
    {
        DBusMessageIter variant;
        dbus_message_iter_recurse(&replyIter, &variant);

        const char *address;
        dbus_message_iter_get_arg(&variant, &address);

        dbus_message_unref(reply);
        return std::string(address);
    }

    dbus_message_unref(reply);
    return "";
}

std::string LinuxBluetooth::getDeviceName(const char *devicePath)
{
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", devicePath, "org.freedesktop.DBus.Properties", "Get");
    if (!msg)
    {
        return "";
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);

    const char *interface = "org.bluez.Device1";
    const char *property = "Name";

    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &property);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return "";
    }

    DBusMessageIter replyIter;
    if (dbus_message_iter_init(reply, &replyIter))
    {
        DBusMessageIter variant;
        dbus_message_iter_recurse(&replyIter, &variant);

        const char *name;
        dbus_message_iter_get_arg(&variant, &name);

        dbus_message_unref(reply);
        return std::string(name);
    }

    dbus_message_unref(reply);
    return "";
}

void LinuxBluetooth::handleDeviceFound(const std::string &deviceAddress, const std::string &deviceName)
{
    spdlog::info("Found BLE device: {} ({})", deviceAddress, deviceName);

    std::lock_guard<std::mutex> lock(devicesMutex);

    // Check if device is already connected
    if (connectedDevices.find(deviceAddress) != connectedDevices.end())
    {
        return;
    }

    // Connect to device
    if (connectToDevice(deviceAddress))
    {
        std::string peerId = "peer_" + deviceAddress.substr(0, 8);
        connectedDevices[deviceAddress] = peerId;
        deviceNames[deviceAddress] = deviceName;

        spdlog::info("Connected to BLE device: {} (Peer ID: {})", deviceAddress, peerId);
    }
}

bool LinuxBluetooth::connectToDevice(const std::string &deviceAddress)
{
    // Find device path
    std::string devicePath = findDevicePath(deviceAddress);
    if (devicePath.empty())
    {
        return false;
    }

    // Connect to device
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", devicePath.c_str(), "org.bluez.Device1", "Connect");
    if (!msg)
    {
        return false;
    }

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return false;
    }

    dbus_message_unref(reply);
    spdlog::info("Connection request sent to device: {}", deviceAddress);
    return true;
}

std::string LinuxBluetooth::findDevicePath(const std::string &deviceAddress)
{
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    if (!msg)
    {
        return "";
    }

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return "";
    }

    DBusMessageIter iter;
    if (dbus_message_iter_init(reply, &iter))
    {
        DBusMessageIter dict;
        dbus_message_iter_recurse(&iter, &dict);

        do
        {
            DBusMessageIter entry;
            dbus_message_iter_recurse(&dict, &entry);

            DBusMessageIter key;
            dbus_message_iter_recurse(&entry, &key);
            const char *path;
            dbus_message_iter_get_arg(&key, &path);

            // Check if this is a device with matching address
            if (strstr(path, "/org/bluez/hci") != nullptr && strstr(path, "/dev_") != nullptr)
            {
                std::string foundAddress = getDeviceAddress(path);
                if (foundAddress == deviceAddress)
                {
                    dbus_message_unref(reply);
                    return std::string(path);
                }
            }
        } while (dbus_message_iter_next(&dict));
    }

    dbus_message_unref(reply);
    return "";
}

bool LinuxBluetooth::startAdvertising()
{
    // Create advertising manager
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", adapterPath.c_str(), "org.bluez.LEAdvertisingManager1", "RegisterAdvertisement");
    if (!msg)
    {
        return false;
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);

    // Advertising path
    std::string advertisingPath = adapterPath + "/advertising0";
    const char *advertisingPathStr = advertisingPath.c_str();
    dbus_message_iter_append_arg(&iter, DBUS_TYPE_OBJECT_PATH, &advertisingPathStr);

    // Empty options dictionary
    DBusMessageIter options;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &options);
    dbus_message_iter_close_container(&iter, &options);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return false;
    }

    dbus_message_unref(reply);
    spdlog::debug("BLE advertising started");
    return true;
}

void LinuxBluetooth::stopAdvertising()
{
    // Stop advertising
    spdlog::debug("BLE advertising stopped");
}

bool LinuxBluetooth::writeCharacteristicValue(const std::string &deviceAddress, const std::vector<uint8_t> &data)
{
    // Find device path
    std::string devicePath = findDevicePath(deviceAddress);
    if (devicePath.empty())
    {
        return false;
    }

    // Find characteristic path
    std::string charPath = findCharacteristicPath(devicePath);
    if (charPath.empty())
    {
        return false;
    }

    // Write to characteristic
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", charPath.c_str(), "org.bluez.GattCharacteristic1", "WriteValue");
    if (!msg)
    {
        return false;
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);

    // Data array
    DBusMessageIter array;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "y", &array);
    dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE, &data[0], data.size());
    dbus_message_iter_close_container(&iter, &array);

    // Empty options dictionary
    DBusMessageIter options;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &options);
    dbus_message_iter_close_container(&iter, &options);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return false;
    }

    dbus_message_unref(reply);
    spdlog::debug("Wrote {} bytes to characteristic for device: {}", data.size(), deviceAddress);
    return true;
}

std::string LinuxBluetooth::findCharacteristicPath(const std::string &devicePath)
{
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", devicePath.c_str(), "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    if (!msg)
    {
        return "";
    }

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return "";
    }

    DBusMessageIter iter;
    if (dbus_message_iter_init(reply, &iter))
    {
        DBusMessageIter dict;
        dbus_message_iter_recurse(&iter, &dict);

        do
        {
            DBusMessageIter entry;
            dbus_message_iter_recurse(&dict, &entry);

            DBusMessageIter key;
            dbus_message_iter_recurse(&entry, &key);
            const char *path;
            dbus_message_iter_get_arg(&key, &path);

            // Check if this is our characteristic
            if (strstr(path, "/char") != nullptr)
            {
                std::string charUuid = getCharacteristicUUID(path);
                if (charUuid == CHARACTERISTIC_UUID)
                {
                    dbus_message_unref(reply);
                    return std::string(path);
                }
            }
        } while (dbus_message_iter_next(&dict));
    }

    dbus_message_unref(reply);
    return "";
}

std::string LinuxBluetooth::getCharacteristicUUID(const char *charPath)
{
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", charPath, "org.freedesktop.DBus.Properties", "Get");
    if (!msg)
    {
        return "";
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);

    const char *interface = "org.bluez.GattCharacteristic1";
    const char *property = "UUID";

    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &property);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        return "";
    }

    DBusMessageIter replyIter;
    if (dbus_message_iter_init(reply, &replyIter))
    {
        DBusMessageIter variant;
        dbus_message_iter_recurse(&replyIter, &variant);

        const char *uuid;
        dbus_message_iter_get_arg(&variant, &uuid);

        dbus_message_unref(reply);
        return std::string(uuid);
    }

    dbus_message_unref(reply);
    return "";
}

void LinuxBluetooth::notifySubscribers(const std::vector<uint8_t> &data)
{
    // Update characteristic value for all subscribers
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", characteristicPath.c_str(), "org.freedesktop.DBus.Properties", "Set");
    if (!msg)
    {
        return;
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);

    const char *interface = "org.bluez.GattCharacteristic1";
    const char *property = "Value";

    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_arg(&iter, DBUS_TYPE_STRING, &property);

    DBusMessageIter variant;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, "ay", &variant);

    DBusMessageIter array;
    dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "y", &array);
    dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE, &data[0], data.size());
    dbus_message_iter_close_container(&variant, &array);
    dbus_message_iter_close_container(&iter, &variant);

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (reply)
    {
        dbus_message_unref(reply);
        spdlog::debug("Notified {} subscribers with {} bytes", subscribedDevices.size(), data.size());
    }
}

std::string LinuxBluetooth::generateLocalPeerId()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::stringstream ss;
    for (size_t i = 0; i < constants::BLE_PEER_ID_LENGTH_CHARS / 2; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(gen);
    }

    return ss.str();
}

void LinuxBluetooth::processReceivedData(const std::string &deviceAddress, const std::vector<uint8_t> &data)
{
    if (data.size() < constants::BLE_MIN_PACKET_SIZE_BYTES)
    {
        spdlog::warn("Received packet too small from device: {}", deviceAddress);
        return;
    }

    if (data.size() > constants::BLE_MAX_PACKET_SIZE_BYTES)
    {
        spdlog::warn("Received packet too large from device: {}", deviceAddress);
        return;
    }

    try
    {
        PacketSerializer serializer;
        BitchatPacket packet = serializer.deserializePacket(data);

        // Validate packet
        if (packet.version == 0 || packet.version > 1)
        {
            spdlog::warn("Invalid packet version {} from device: {}", packet.version, deviceAddress);
            return;
        }

        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet);
            spdlog::debug("Processed packet from device: {}", deviceAddress);
        }
    }
    catch (const std::exception &e)
    {
        spdlog::error("Failed to deserialize packet from device {}: {}", deviceAddress, e.what());
    }
}

} // namespace bitchat
