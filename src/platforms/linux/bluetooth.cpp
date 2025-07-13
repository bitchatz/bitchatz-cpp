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
#include <dbus/dbus.h>

namespace bitchat
{

// Static member initialization
const std::string LinuxBluetooth::SERVICE_UUID = constants::BLE_SERVICE_UUID;
const std::string LinuxBluetooth::CHARACTERISTIC_UUID = constants::BLE_CHARACTERISTIC_UUID;

// GATT Application interface implementation
static DBusHandlerResult gatt_message_handler(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
    LinuxBluetooth *bt = static_cast<LinuxBluetooth*>(user_data);
    return bt->handleGattMessage(conn, msg);
}

LinuxBluetooth::LinuxBluetooth()
    : ready(false)
    , stopThreads(false)
    , dbusConn(nullptr)
    , hciSocket(-1)
    , deviceId(-1)
    , adapterPath("")
    , servicePath("")
    , characteristicPath("")
    , gattApplicationPath("")
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
    try
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
    catch (const std::exception& e)
    {
        spdlog::error("Exception during Bluetooth initialization: {}", e.what());
        return false;
    }
    catch (...)
    {
        spdlog::error("Unknown exception during Bluetooth initialization");
        return false;
    }
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
    DBusError error;
    dbus_error_init(&error);

    dbusConn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
    if (dbus_error_is_set(&error))
    {
        spdlog::error("Failed to connect to DBus: {}", error.message);
        dbus_error_free(&error);
        return false;
    }

    // We don't need to request a service name for client operations
    // Just connect to the system bus to communicate with BlueZ
    spdlog::info("DBus connection established");
    
    // Check if BlueZ is running
    DBusMessage *msg = dbus_message_new_method_call("org.freedesktop.DBus", "/", "org.freedesktop.DBus", "ListNames");
    if (!msg)
    {
        spdlog::error("Failed to create DBus message for service check");
        return false;
    }

    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        spdlog::error("No reply from DBus for service check");
        return false;
    }

    // Check if org.bluez is in the list of services
    DBusMessageIter iter;
    if (dbus_message_iter_init(reply, &iter))
    {
        DBusMessageIter array;
        dbus_message_iter_recurse(&iter, &array);
        
        bool bluezFound = false;
        do
        {
            const char *service;
            dbus_message_iter_get_basic(&array, &service);
            if (strcmp(service, "org.bluez") == 0)
            {
                bluezFound = true;
                break;
            }
        } while (dbus_message_iter_next(&array));

        if (!bluezFound)
        {
            spdlog::error("BlueZ service not found. Make sure bluetooth service is running");
            dbus_message_unref(reply);
            return false;
        }
    }

    dbus_message_unref(reply);
    spdlog::info("BlueZ service found and available");
    return true;
}

void LinuxBluetooth::cleanupDbus()
{
    if (dbusConn)
    {
        // Note: GATT objects are not registered in simplified mode
        // so we don't need to unregister them
        
        dbus_connection_unref(dbusConn);
        dbusConn = nullptr;
        spdlog::info("DBus connection closed");
    }
}

bool LinuxBluetooth::findBluetoothAdapter()
{
    if (!dbusConn)
    {
        spdlog::error("DBus connection not available");
        return false;
    }

    // Try a simpler approach first - just check if we can find any HCI adapter
    spdlog::debug("Trying simple adapter detection...");
    
    // List all HCI adapters using a simpler method
    for (int i = 0; i < 10; i++) // Check first 10 possible adapters
    {
        std::string adapterPath = "/org/bluez/hci" + std::to_string(i);
        spdlog::debug("Checking adapter path: {}", adapterPath);
        
        DBusMessage *msg = dbus_message_new_method_call("org.bluez", adapterPath.c_str(), "org.freedesktop.DBus.Properties", "Get");
        if (!msg)
        {
            continue;
        }

        DBusMessageIter iter;
        dbus_message_iter_init_append(msg, &iter);

        const char *interface = "org.bluez.Adapter1";
        const char *property = "Powered";

        dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface);
        dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &property);

        DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
        dbus_message_unref(msg);

        if (reply)
        {
            spdlog::info("Found Bluetooth adapter: {}", adapterPath);
            this->adapterPath = adapterPath;
            dbus_message_unref(reply);
            return true;
        }
    }

    spdlog::debug("Simple detection failed, trying managed objects approach...");
    
    // Fallback to the original method
    DBusMessage *msg = dbus_message_new_method_call("org.bluez", "/", "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");
    if (!msg)
    {
        spdlog::error("Failed to create DBus message");
        return false;
    }

    spdlog::debug("Sending DBus message...");
    DBusMessage *reply = dbus_connection_send_with_reply_and_block(dbusConn, msg, -1, nullptr);
    dbus_message_unref(msg);

    if (!reply)
    {
        spdlog::error("No reply from BlueZ DBus service");
        return false;
    }

    spdlog::debug("Got reply from BlueZ, processing...");

    DBusMessageIter iter;
    if (!dbus_message_iter_init(reply, &iter))
    {
        spdlog::error("Failed to initialize message iterator");
        dbus_message_unref(reply);
        return false;
    }

    spdlog::debug("Initialized message iterator, recursing to dict...");
    DBusMessageIter dict;
    dbus_message_iter_recurse(&iter, &dict);

    spdlog::debug("Iterating through managed objects...");
    do
    {
        DBusMessageIter entry;
        dbus_message_iter_recurse(&dict, &entry);

        DBusMessageIter key;
        dbus_message_iter_recurse(&entry, &key);

        const char *path = nullptr;
        dbus_message_iter_get_basic(&key, &path);

        if (path)
        {
            spdlog::debug("Checking path: {}", path);

            // Check if this is a Bluetooth adapter
            if (strstr(path, "/org/bluez/hci") != nullptr)
            {
                adapterPath = path;
                spdlog::info("Found Bluetooth adapter: {}", adapterPath);
                dbus_message_unref(reply);
                return true;
            }
        }
    } while (dbus_message_iter_next(&dict));

    spdlog::error("No Bluetooth adapter found in managed objects");
    dbus_message_unref(reply);
    return false;
}

bool LinuxBluetooth::setupGattService()
{
    // For now, we'll use a simpler approach without full GATT server
    // Just set up the paths for potential future use
    gattApplicationPath = "/org/bluez/bitchat/app" + localPeerId.substr(0, 8);
    servicePath = gattApplicationPath + "/service0";
    characteristicPath = servicePath + "/char0";

    spdlog::info("GATT service paths configured (simplified mode): {}", servicePath);
    return true;
}

bool LinuxBluetooth::registerGattApplication()
{
    // Skip GATT application registration for now
    // We'll focus on advertising and scanning
    spdlog::info("Skipping GATT application registration (simplified mode)");
    return true;
}

bool LinuxBluetooth::createGattApplicationObject()
{
    // Skip GATT object creation for now
    spdlog::info("Skipping GATT object creation (simplified mode)");
    return true;
}

DBusHandlerResult LinuxBluetooth::handleGattMessage(DBusConnection *conn, DBusMessage *msg)
{
    const char *interface = dbus_message_get_interface(msg);
    const char *method = dbus_message_get_member(msg);
    const char *path = dbus_message_get_path(msg);

    if (!interface || !method || !path)
    {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    spdlog::debug("GATT message: {} {} {}", path, interface, method);

    // Handle ObjectManager interface
    if (strcmp(interface, "org.freedesktop.DBus.ObjectManager") == 0)
    {
        if (strcmp(method, "GetManagedObjects") == 0)
        {
            return handleGattGetManagedObjects(conn, msg);
        }
    }
    // Handle Properties interface
    else if (strcmp(interface, "org.freedesktop.DBus.Properties") == 0)
    {
        if (strcmp(method, "Get") == 0)
        {
            return handleGattGetProperty(conn, msg);
        }
        else if (strcmp(method, "GetAll") == 0)
        {
            return handleGattGetAllProperties(conn, msg);
        }
    }
    // Handle GATT Service interface
    else if (strcmp(interface, "org.bluez.GattService1") == 0)
    {
        // Service interface methods if needed
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }
    // Handle GATT Characteristic interface
    else if (strcmp(interface, "org.bluez.GattCharacteristic1") == 0)
    {
        if (strcmp(method, "ReadValue") == 0)
        {
            return handleGattReadValue(conn, msg);
        }
        else if (strcmp(method, "WriteValue") == 0)
        {
            return handleGattWriteValue(conn, msg);
        }
        else if (strcmp(method, "StartNotify") == 0)
        {
            return handleGattStartNotify(conn, msg);
        }
        else if (strcmp(method, "StopNotify") == 0)
        {
            return handleGattStopNotify(conn, msg);
        }
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

DBusHandlerResult LinuxBluetooth::handleGattGetProperty(DBusConnection *conn, DBusMessage *msg)
{
    DBusMessageIter iter;
    if (!dbus_message_iter_init(msg, &iter))
    {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    const char *interface;
    const char *property;
    
    dbus_message_iter_get_basic(&iter, &interface);
    dbus_message_iter_next(&iter);
    dbus_message_iter_get_basic(&iter, &property);

    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
    {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    DBusMessageIter replyIter;
    dbus_message_iter_init_append(reply, &replyIter);

    if (strcmp(interface, "org.bluez.GattService1") == 0)
    {
        if (strcmp(property, "UUID") == 0)
        {
            DBusMessageIter variant;
            dbus_message_iter_open_container(&replyIter, DBUS_TYPE_VARIANT, "s", &variant);
            const char *uuid = SERVICE_UUID.c_str();
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &uuid);
            dbus_message_iter_close_container(&replyIter, &variant);
        }
        else if (strcmp(property, "Primary") == 0)
        {
            DBusMessageIter variant;
            dbus_message_iter_open_container(&replyIter, DBUS_TYPE_VARIANT, "b", &variant);
            dbus_bool_t primary = TRUE;
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &primary);
            dbus_message_iter_close_container(&replyIter, &variant);
        }
    }
    else if (strcmp(interface, "org.bluez.GattCharacteristic1") == 0)
    {
        if (strcmp(property, "UUID") == 0)
        {
            DBusMessageIter variant;
            dbus_message_iter_open_container(&replyIter, DBUS_TYPE_VARIANT, "s", &variant);
            const char *uuid = CHARACTERISTIC_UUID.c_str();
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &uuid);
            dbus_message_iter_close_container(&replyIter, &variant);
        }
        else if (strcmp(property, "Service") == 0)
        {
            DBusMessageIter variant;
            dbus_message_iter_open_container(&replyIter, DBUS_TYPE_VARIANT, "o", &variant);
            const char *service = servicePath.c_str();
            dbus_message_iter_append_basic(&variant, DBUS_TYPE_OBJECT_PATH, &service);
            dbus_message_iter_close_container(&replyIter, &variant);
        }
        else if (strcmp(property, "Value") == 0)
        {
            DBusMessageIter variant;
            dbus_message_iter_open_container(&replyIter, DBUS_TYPE_VARIANT, "ay", &variant);
            DBusMessageIter array;
            dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "y", &array);
            // Return empty value for now
            dbus_message_iter_close_container(&variant, &array);
            dbus_message_iter_close_container(&replyIter, &variant);
        }
        else if (strcmp(property, "Flags") == 0)
        {
            DBusMessageIter variant;
            dbus_message_iter_open_container(&replyIter, DBUS_TYPE_VARIANT, "as", &variant);
            DBusMessageIter array;
            dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "s", &array);
            
            const char *flags[] = {"read", "write", "notify", "write-without-response"};
            for (int i = 0; i < 4; i++)
            {
                dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &flags[i]);
            }
            
            dbus_message_iter_close_container(&variant, &array);
            dbus_message_iter_close_container(&replyIter, &variant);
        }
    }

    dbus_connection_send(conn, reply, nullptr);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult LinuxBluetooth::handleGattGetAllProperties(DBusConnection *conn, DBusMessage *msg)
{
    DBusMessageIter iter;
    if (!dbus_message_iter_init(msg, &iter))
    {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    const char *interface;
    dbus_message_iter_get_basic(&iter, &interface);

    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
    {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    DBusMessageIter replyIter;
    dbus_message_iter_init_append(reply, &replyIter);

    DBusMessageIter dict;
    dbus_message_iter_open_container(&replyIter, DBUS_TYPE_ARRAY, "{sv}", &dict);

    if (strcmp(interface, "org.bluez.GattService1") == 0)
    {
        // Add UUID property
        DBusMessageIter entry;
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        const char *key = "UUID";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
        
        DBusMessageIter variant;
        dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "s", &variant);
        const char *uuid = SERVICE_UUID.c_str();
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &uuid);
        dbus_message_iter_close_container(&entry, &variant);
        dbus_message_iter_close_container(&dict, &entry);

        // Add Primary property
        dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
        key = "Primary";
        dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
        
        dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "b", &variant);
        dbus_bool_t primary = TRUE;
        dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &primary);
        dbus_message_iter_close_container(&entry, &variant);
        dbus_message_iter_close_container(&dict, &entry);
    }

    dbus_message_iter_close_container(&replyIter, &dict);
    dbus_connection_send(conn, reply, nullptr);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult LinuxBluetooth::handleGattGetManagedObjects(DBusConnection *conn, DBusMessage *msg)
{
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
    {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(reply, &iter);

    DBusMessageIter dict;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{oa{sa{sv}}}", &dict);

    // Add service object
    DBusMessageIter entry;
    dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
    const char *servicePathStr = servicePath.c_str();
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH, &servicePathStr);

    DBusMessageIter interfaces;
    dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY, "{sa{sv}}", &interfaces);

    // Add GattService1 interface
    DBusMessageIter interfaceEntry;
    dbus_message_iter_open_container(&interfaces, DBUS_TYPE_DICT_ENTRY, nullptr, &interfaceEntry);
    const char *interface = "org.bluez.GattService1";
    dbus_message_iter_append_basic(&interfaceEntry, DBUS_TYPE_STRING, &interface);

    DBusMessageIter properties;
    dbus_message_iter_open_container(&interfaceEntry, DBUS_TYPE_ARRAY, "{sv}", &properties);

    // UUID property
    DBusMessageIter propEntry;
    dbus_message_iter_open_container(&properties, DBUS_TYPE_DICT_ENTRY, nullptr, &propEntry);
    const char *key = "UUID";
    dbus_message_iter_append_basic(&propEntry, DBUS_TYPE_STRING, &key);
    
    DBusMessageIter variant;
    dbus_message_iter_open_container(&propEntry, DBUS_TYPE_VARIANT, "s", &variant);
    const char *uuid = SERVICE_UUID.c_str();
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &uuid);
    dbus_message_iter_close_container(&propEntry, &variant);
    dbus_message_iter_close_container(&properties, &propEntry);

    // Primary property
    dbus_message_iter_open_container(&properties, DBUS_TYPE_DICT_ENTRY, nullptr, &propEntry);
    key = "Primary";
    dbus_message_iter_append_basic(&propEntry, DBUS_TYPE_STRING, &key);
    
    dbus_message_iter_open_container(&propEntry, DBUS_TYPE_VARIANT, "b", &variant);
    dbus_bool_t primary = TRUE;
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &primary);
    dbus_message_iter_close_container(&propEntry, &variant);
    dbus_message_iter_close_container(&properties, &propEntry);

    dbus_message_iter_close_container(&interfaceEntry, &properties);
    dbus_message_iter_close_container(&interfaces, &interfaceEntry);
    dbus_message_iter_close_container(&entry, &interfaces);
    dbus_message_iter_close_container(&dict, &entry);

    // Add characteristic object
    dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, nullptr, &entry);
    const char *charPathStr = characteristicPath.c_str();
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH, &charPathStr);

    dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY, "{sa{sv}}", &interfaces);

    // Add GattCharacteristic1 interface
    dbus_message_iter_open_container(&interfaces, DBUS_TYPE_DICT_ENTRY, nullptr, &interfaceEntry);
    interface = "org.bluez.GattCharacteristic1";
    dbus_message_iter_append_basic(&interfaceEntry, DBUS_TYPE_STRING, &interface);

    dbus_message_iter_open_container(&interfaceEntry, DBUS_TYPE_ARRAY, "{sv}", &properties);

    // UUID property
    dbus_message_iter_open_container(&properties, DBUS_TYPE_DICT_ENTRY, nullptr, &propEntry);
    key = "UUID";
    dbus_message_iter_append_basic(&propEntry, DBUS_TYPE_STRING, &key);
    
    dbus_message_iter_open_container(&propEntry, DBUS_TYPE_VARIANT, "s", &variant);
    uuid = CHARACTERISTIC_UUID.c_str();
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &uuid);
    dbus_message_iter_close_container(&propEntry, &variant);
    dbus_message_iter_close_container(&properties, &propEntry);

    // Service property
    dbus_message_iter_open_container(&properties, DBUS_TYPE_DICT_ENTRY, nullptr, &propEntry);
    key = "Service";
    dbus_message_iter_append_basic(&propEntry, DBUS_TYPE_STRING, &key);
    
    dbus_message_iter_open_container(&propEntry, DBUS_TYPE_VARIANT, "o", &variant);
    const char *service = servicePath.c_str();
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_OBJECT_PATH, &service);
    dbus_message_iter_close_container(&propEntry, &variant);
    dbus_message_iter_close_container(&properties, &propEntry);

    // Value property
    dbus_message_iter_open_container(&properties, DBUS_TYPE_DICT_ENTRY, nullptr, &propEntry);
    key = "Value";
    dbus_message_iter_append_basic(&propEntry, DBUS_TYPE_STRING, &key);
    
    dbus_message_iter_open_container(&propEntry, DBUS_TYPE_VARIANT, "ay", &variant);
    DBusMessageIter array;
    dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "y", &array);
    // Empty value for now
    dbus_message_iter_close_container(&variant, &array);
    dbus_message_iter_close_container(&propEntry, &variant);
    dbus_message_iter_close_container(&properties, &propEntry);

    // Flags property
    dbus_message_iter_open_container(&properties, DBUS_TYPE_DICT_ENTRY, nullptr, &propEntry);
    key = "Flags";
    dbus_message_iter_append_basic(&propEntry, DBUS_TYPE_STRING, &key);
    
    dbus_message_iter_open_container(&propEntry, DBUS_TYPE_VARIANT, "as", &variant);
    dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "s", &array);
    
    const char *flags[] = {"read", "write", "notify", "write-without-response"};
    for (int i = 0; i < 4; i++)
    {
        dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &flags[i]);
    }
    
    dbus_message_iter_close_container(&variant, &array);
    dbus_message_iter_close_container(&propEntry, &variant);
    dbus_message_iter_close_container(&properties, &propEntry);

    dbus_message_iter_close_container(&interfaceEntry, &properties);
    dbus_message_iter_close_container(&interfaces, &interfaceEntry);
    dbus_message_iter_close_container(&entry, &interfaces);
    dbus_message_iter_close_container(&dict, &entry);

    dbus_message_iter_close_container(&iter, &dict);
    dbus_connection_send(conn, reply, nullptr);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult LinuxBluetooth::handleGattReadValue(DBusConnection *conn, DBusMessage *msg)
{
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (!reply)
    {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    DBusMessageIter iter;
    dbus_message_iter_init_append(reply, &iter);

    DBusMessageIter array;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "y", &array);
    // Return empty value for now
    dbus_message_iter_close_container(&iter, &array);

    dbus_connection_send(conn, reply, nullptr);
    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult LinuxBluetooth::handleGattWriteValue(DBusConnection *conn, DBusMessage *msg)
{
    DBusMessageIter iter;
    if (!dbus_message_iter_init(msg, &iter))
    {
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    }

    // Extract the data from the message
    DBusMessageIter array;
    dbus_message_iter_recurse(&iter, &array);
    
    int arrayLen;
    const uint8_t *data;
    dbus_message_iter_get_fixed_array(&array, &data, &arrayLen);

    if (arrayLen > 0)
    {
        std::vector<uint8_t> packetData(data, data + arrayLen);
        processReceivedData("unknown", packetData);
    }

    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply)
    {
        dbus_connection_send(conn, reply, nullptr);
        dbus_message_unref(reply);
    }

    return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult LinuxBluetooth::handleGattStartNotify(DBusConnection *conn, DBusMessage *msg)
{
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply)
    {
        dbus_connection_send(conn, reply, nullptr);
        dbus_message_unref(reply);
    }
    return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult LinuxBluetooth::handleGattStopNotify(DBusConnection *conn, DBusMessage *msg)
{
    DBusMessage *reply = dbus_message_new_method_return(msg);
    if (reply)
    {
        dbus_connection_send(conn, reply, nullptr);
        dbus_message_unref(reply);
    }
    return DBUS_HANDLER_RESULT_HANDLED;
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

    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &property);

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
            dbus_message_iter_get_basic(&devicePath, &path);

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

    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &property);

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
            dbus_message_iter_get_basic(&array, &uuid);

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

    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &property);

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
        dbus_message_iter_get_basic(&variant, &address);

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

    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &property);

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
        dbus_message_iter_get_basic(&variant, &name);

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
            dbus_message_iter_get_basic(&key, &path);

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
    // For simplified mode, we'll just log that advertising would start
    // In a full implementation, we would register an advertising object
    spdlog::debug("BLE advertising would start (simplified mode)");
    return true;
}

void LinuxBluetooth::stopAdvertising()
{
    // Stop advertising
    spdlog::debug("BLE advertising stopped");
}

bool LinuxBluetooth::writeCharacteristicValue(const std::string &deviceAddress, const std::vector<uint8_t> &data)
{
    // In simplified mode, we can't write to characteristics
    // This would require a full GATT server implementation
    spdlog::debug("Characteristic write not implemented in simplified mode");
    return false;
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
            dbus_message_iter_get_basic(&key, &path);

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

    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &interface);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &property);

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
        dbus_message_iter_get_basic(&variant, &uuid);

        dbus_message_unref(reply);
        return std::string(uuid);
    }

    dbus_message_unref(reply);
    return "";
}

void LinuxBluetooth::notifySubscribers(const std::vector<uint8_t> &data)
{
    // In simplified mode, we can't notify subscribers
    // This would require a full GATT server implementation
    spdlog::debug("Subscriber notification not implemented in simplified mode");
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
