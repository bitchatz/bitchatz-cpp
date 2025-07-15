#include "platforms/linux/bluetooth.h"
#include "bitchat/core/constants.h"
#include "bitchat/protocol/packet_serializer.h"
#include <atomic>
#include <bluez-dbus-cpp/Adapter1.h>
#include <bluez-dbus-cpp/Client.h>
#include <bluez-dbus-cpp/Device1.h>
#include <bluez-dbus-cpp/GattCharacteristicBuilder.h>
#include <bluez-dbus-cpp/GattService1.h>
#include <bluez-dbus-cpp/GenericCharacteristic.h>
#include <bluez-dbus-cpp/LEAdvertisingManager1.h>
#include <bluez-dbus-cpp/Util.h>
#include <bluez-dbus-cpp/bluez.h>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <random>
#include <sdbus-c++/sdbus-c++.h>
#include <set>
#include <spdlog/spdlog.h>
#include <thread>

using namespace org::bluez;

// Constants
constexpr const char *ADV_PATH = "/org/bluez/bitchat/advertisement1";

// Forward declarations
class LinuxBluetooth;

// ChatClient class for managing individual device connections
class ChatClient : public Client
{
public:
    ChatClient(sdbus::ObjectPath path, uint16_t usable_mtu, std::vector<uint8_t> &&initialValue)
        : Client{path, usable_mtu}
        , value{std::move(initialValue)}
    {
    }

    void setData(std::vector<uint8_t> &&value)
    {
        this->value = std::move(value);
    }

    void setData(const std::vector<uint8_t> &value)
    {
        this->value.assign(value.begin(), value.end());
    }

    std::vector<uint8_t> &&getData()
    {
        return std::move(value);
    }

    const std::vector<uint8_t> &getDataRef() const
    {
        return value;
    }

private:
    std::vector<uint8_t> value;
};

// ChatCharacteristic class for handling BLE communication
class ChatCharacteristic : public GattCharacteristic1
{
public:
    ChatCharacteristic(std::shared_ptr<GattService1> service,
                       std::shared_ptr<sdbus::IConnection> connection,
                       std::string uuid,
                       LinuxBluetooth *bluetooth)
        : GattCharacteristic1{std::move(service), std::move(uuid), false, false, true, false}
        , connection{std::move(connection)}
        , bluetooth(bluetooth)
    {
        // Properties are set in the constructor: read=true, write=true, notify=true, indicate=false
        // Add flags for the characteristic
        addFlag("read");
        addFlag("write");
        addFlag("write-without-response");
        addFlag("notify");
    }

    static std::shared_ptr<ChatCharacteristic> create(std::shared_ptr<GattService1> service,
                                                      std::shared_ptr<sdbus::IConnection> connection,
                                                      std::string uuid,
                                                      LinuxBluetooth *bluetooth)
    {
        auto characteristic = std::shared_ptr<ChatCharacteristic>(new ChatCharacteristic(std::move(service), std::move(connection), std::move(uuid), bluetooth));
        // Register with service
        characteristic->registerWithService(characteristic);
        return characteristic;
    }

    // Public method to send notifications
    void sendNotification(const std::vector<uint8_t> &data)
    {
        // Update the characteristic value
        value_ = data;

        // Emit property changed signal to notify subscribers
        emitPropertyChangedSignal("Value");

        spdlog::info("ChatCharacteristic::sendNotification sent {} bytes to {} clients", data.size(), clients.size());
    }

protected:
    virtual std::vector<uint8_t> ReadValue([[maybe_unused]] const std::map<std::string, sdbus::Variant> &options) override
    {
        // Return current value for read operations
        spdlog::debug("ChatCharacteristic::ReadValue called, returning {} bytes", value_.size());
        return value_;
    }

    virtual void WriteValue(const std::vector<uint8_t> &value, [[maybe_unused]] const std::map<std::string, sdbus::Variant> &options) override
    {
        // Update the characteristic value
        value_ = value;

        spdlog::info("ChatCharacteristic::WriteValue received {} bytes", value.size());

        // Forward the received data to the LinuxBluetooth class for processing
        if (bluetooth && value.size() >= bitchat::constants::BLE_MIN_PACKET_SIZE_BYTES)
        {
            bluetooth->onDataReceived(value);
        }
        else if (value.size() < bitchat::constants::BLE_MIN_PACKET_SIZE_BYTES)
        {
            spdlog::info("Ignoring packet too small: {} bytes", value.size());
        }
    }

    void StartNotify(const std::map<std::string, sdbus::Variant> &options) override
    {
        spdlog::info("ChatCharacteristic::StartNotify called");

        // Get client info for tracking
        auto client = getClient(options);
        spdlog::info("ChatCharacteristic::StartNotify for client '{}'", client->getPath());

        // Add to subscribed clients
        if (bluetooth)
        {
            bluetooth->addSubscribedClient(client);
        }
    }

    void StopNotify(const std::map<std::string, sdbus::Variant> &options) override
    {
        spdlog::info("ChatCharacteristic::StopNotify called");

        if (options.size() != 0)
        {
            auto client = getClient(options);
            spdlog::info("ChatCharacteristic::StopNotify for client '{}'", client->getPath());

            // Remove from subscribed clients
            if (bluetooth)
            {
                bluetooth->removeSubscribedClient(client);
            }
        }
    }

protected:
    std::shared_ptr<ChatClient> getClient(const std::map<std::string, sdbus::Variant> &options)
    {
        uint16_t real_mtu, usable_mtu;
        std::tie(real_mtu, usable_mtu) = Util::getMTUFromOptions(options);

        auto path = Util::getObjectPathFromOptions(options);
        auto iter = clients.find(path);
        if (iter == clients.end())
        {
            spdlog::info("ChatCharacteristic::getClient - creating client '{}'", path);
            auto client = std::make_shared<ChatClient>(path, usable_mtu, std::vector<uint8_t>());
            iter = clients.insert(std::make_pair(path, client)).first;
        }
        return iter->second;
    }

    std::map<sdbus::ObjectPath, std::shared_ptr<ChatClient>> clients;
    std::shared_ptr<sdbus::IConnection> connection;
    LinuxBluetooth *bluetooth;
};

struct LinuxBluetooth::Impl
{
    std::string localPeerId;

    std::shared_ptr<sdbus::IConnection> connection;
    std::shared_ptr<GattApplication1> app;
    std::shared_ptr<GattService1> chatService;
    std::shared_ptr<ChatCharacteristic> chatCharacteristic;
    std::shared_ptr<LEAdvertisingManager1> advManager;
    std::shared_ptr<Adapter1> adapter;
    std::shared_ptr<LEAdvertisement1> advertisement; // Store advertisement object

    // Collections for managing BLE connections (equivalent to Objective-C)
    std::map<std::string, std::shared_ptr<Device1>> connectedDevices;  // Connected devices
    std::map<std::string, std::shared_ptr<ChatClient>> deviceClients;  // Clients for each device
    std::set<std::shared_ptr<ChatClient>> subscribedClients;           // Subscribed clients
    std::map<std::string, std::shared_ptr<Device1>> discoveredDevices; // Discovered devices
    std::mutex connectionsMutex;

    std::atomic<bool> ready{false};
    std::atomic<bool> advertisementRegistered{false};
    std::atomic<bool> scanning{false};

    bitchat::PeerDisconnectedCallback peerDisconnectedCallback;
    bitchat::PacketReceivedCallback packetReceivedCallback;

    bitchat::PacketSerializer serializer;

    // Device discovery and connection management
    void onDeviceFound(const std::string &devicePath, const std::string &address, const std::string &name)
    {
        std::lock_guard<std::mutex> lock(connectionsMutex);

        // Check if we already know this device
        if (discoveredDevices.find(devicePath) != discoveredDevices.end())
        {
            spdlog::debug("Device already known: {}", devicePath);
            return;
        }

        // Skip our own device
        if (address == adapter->Address())
        {
            spdlog::debug("Skipping own device: {}", address);
            return;
        }

        spdlog::info("Device discovered: {} ({}) at {}", name, address, devicePath);

        try
        {
            // Create Device1 object for the discovered device
            auto device = std::make_shared<Device1>(*connection, "org.bluez", devicePath);

            // Store the discovered device
            discoveredDevices[devicePath] = device;

            // Check if device is advertising our service
            auto uuids = device->UUIDs();
            spdlog::debug("Device {} has {} UUIDs", name, uuids.size());

            bool hasOurService = false;
            for (const auto &uuid : uuids)
            {
                spdlog::debug("  UUID: {}", uuid);
                if (uuid == bitchat::constants::BLE_SERVICE_UUID)
                {
                    hasOurService = true;
                    spdlog::info("Found our service UUID: {}", uuid);
                    break;
                }
            }

            if (hasOurService)
            {
                spdlog::info("Device has our service, attempting connection...");
                connectToDevice(devicePath);
            }
            else
            {
                spdlog::debug("Device does not have our service: {}", name);
            }
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error creating device object for {}: {}", devicePath, e.what());
        }
    }

    void connectToDevice(const std::string &devicePath)
    {
        try
        {
            auto device = discoveredDevices[devicePath];

            // Check if already connected
            if (device->Connected())
            {
                spdlog::info("Device already connected: {}", devicePath);
                setupDeviceCommunication(devicePath);
                return;
            }

            // Connect to the device
            device->Connect();
            spdlog::info("Connection initiated to device: {}", devicePath);
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error connecting to device {}: {}", devicePath, e.what());
        }
    }

    void discoverServices(const std::string &devicePath)
    {
        try
        {
            auto device = discoveredDevices[devicePath];

            // Check if services are resolved
            if (!device->ServicesResolved())
            {
                spdlog::info("Services not yet resolved for device: {}", devicePath);
                return;
            }

            // Get UUIDs to check if device has our service
            auto uuids = device->UUIDs();
            bool hasOurService = false;
            for (const auto &uuid : uuids)
            {
                if (uuid == bitchat::constants::BLE_SERVICE_UUID)
                {
                    hasOurService = true;
                    break;
                }
            }

            if (hasOurService)
            {
                spdlog::info("Device has our service, setting up communication...");
                setupDeviceCommunication(devicePath);
            }
            else
            {
                spdlog::debug("Device does not have our service: {}", devicePath);
            }
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error discovering services for device {}: {}", devicePath, e.what());
        }
    }

    void setupDeviceCommunication(const std::string &devicePath)
    {
        try
        {
            auto device = discoveredDevices[devicePath];
            std::string peerId = device->Alias().empty() ? device->Address() : device->Alias();
            std::string nickname = device->Name().empty() ? device->Alias() : device->Name();

            // Check if we already have a client for this peer
            std::lock_guard<std::mutex> lock(connectionsMutex);
            if (deviceClients.find(peerId) != deviceClients.end())
            {
                spdlog::debug("Device {} already has a client", peerId);
                return;
            }

            // Create a client for this device
            auto client = std::make_shared<ChatClient>(devicePath, 512, std::vector<uint8_t>());
            deviceClients[peerId] = client;

            spdlog::info("Device {} ({}) added to connected devices", peerId, nickname);
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error setting up device communication for {}: {}", devicePath, e.what());
        }
    }

    // Generate random peer id (8 hex chars)
    std::string generatePeerId()
    {
        std::random_device rd;
        std::uniform_int_distribution<int> dist(0, 15);
        std::string hexChars = "0123456789abcdef";
        std::string id;
        for (size_t i = 0; i < bitchat::constants::BLE_PEER_ID_LENGTH_CHARS; ++i)
            id += hexChars[dist(rd)];
        return id;
    }
};

LinuxBluetooth::LinuxBluetooth()
    : impl(std::make_unique<Impl>())
{
    impl->localPeerId = impl->generatePeerId();
}

LinuxBluetooth::~LinuxBluetooth()
{
    stop();
}

bool LinuxBluetooth::initialize()
{
    try
    {
        spdlog::info("LinuxBluetooth::initialize starting...");

        // 0. Clean up any existing state first
        impl->ready = false;
        impl->advertisementRegistered = false;
        impl->scanning = false;

        // 1. Create system bus connection
        impl->connection = sdbus::createSystemBusConnection();
        spdlog::info("System bus connection created");

        // 1.5. Check if BlueZ service is available
        try
        {
            auto proxy = sdbus::createProxy(*impl->connection, "org.bluez", "/");
            proxy->callMethod("GetManagedObjects")
                .onInterface("org.freedesktop.DBus.ObjectManager")
                .withArguments();
            spdlog::info("BlueZ service is available");
        }
        catch (const std::exception &e)
        {
            spdlog::error("BlueZ service not available: {}", e.what());
            spdlog::error("Please ensure BlueZ is running: sudo systemctl start bluetooth");
            return false;
        }

        // 1.6. Check Bluetooth permissions
        try
        {
            auto proxy = sdbus::createProxy(*impl->connection, "org.bluez", "/org/bluez/hci0");
            proxy->callMethod("Get").onInterface("org.freedesktop.DBus.Properties").withArguments("org.bluez.Adapter1", "Powered");
            spdlog::info("Bluetooth permissions OK");
        }
        catch (const std::exception &e)
        {
            spdlog::error("Bluetooth permission error: {}", e.what());
            spdlog::error("Please ensure user is in bluetooth group: sudo usermod -a -G bluetooth $USER");
            spdlog::error("Then log out and log back in, or restart the system");
            return false;
        }

        // 2. Get Bluetooth Adapter (hci0)
        constexpr const char *BLUEZ_SERVICE = "org.bluez";
        constexpr const char *DEVICE0 = "/org/bluez/hci0";
        constexpr const char *APP_PATH = "/org/bluez/bitchat";

        impl->adapter = std::make_shared<Adapter1>(*impl->connection, BLUEZ_SERVICE, DEVICE0);
        spdlog::info("Adapter created");

        // Ensure adapter is powered on
        if (!impl->adapter->Powered())
        {
            spdlog::info("Powering on adapter...");
            impl->adapter->Powered(true);
            std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Wait for power on
        }

        // Configure adapter for advertising
        impl->adapter->Discoverable(true);
        impl->adapter->Pairable(true);
        impl->adapter->Alias(impl->localPeerId);

        // Additional adapter configuration for better visibility
        try
        {
            // Set discoverable timeout to 0 (always discoverable)
            impl->adapter->DiscoverableTimeout(0);
            spdlog::info("Set discoverable timeout to 0 (always discoverable)");
        }
        catch (const std::exception &e)
        {
            spdlog::warn("Could not set discoverable timeout: {}", e.what());
        }

        spdlog::info("Adapter configured:");
        spdlog::info("  Name: {}", impl->adapter->Name());
        spdlog::info("  Address: {}", impl->adapter->Address());
        spdlog::info("  Powered: {}", impl->adapter->Powered());
        spdlog::info("  Discoverable: {}", impl->adapter->Discoverable());
        spdlog::info("  Pairable: {}", impl->adapter->Pairable());
        spdlog::info("  Alias: {}", impl->adapter->Alias());

        // 3. Create GATT application/service/characteristic
        spdlog::info("Using Service UUID: {}", bitchat::constants::BLE_SERVICE_UUID);
        spdlog::info("Using Characteristic UUID: {}", bitchat::constants::BLE_CHARACTERISTIC_UUID);

        impl->app = std::make_shared<GattApplication1>(impl->connection, APP_PATH);
        spdlog::info("GATT application created");

        impl->chatService = std::make_shared<GattService1>(impl->app, "chat", bitchat::constants::BLE_SERVICE_UUID);
        spdlog::info("GATT service created");

        // Create characteristic with notify/write-without-response/read
        impl->chatCharacteristic = ChatCharacteristic::create(
            impl->chatService, impl->connection, bitchat::constants::BLE_CHARACTERISTIC_UUID, this);
        spdlog::info("GATT characteristic created and registered");

        // Add service to app and register
        auto gattMgr = GattManager1(impl->connection, "org.bluez", "/org/bluez/hci0");
        spdlog::info("GATT manager created");

        // Register GATT application and then register advertisement in the success callback
        gattMgr.RegisterApplicationAsync(impl->app->getPath(), {}).uponReplyInvoke([this](const sdbus::Error *error)
                                                                                   {
                if (error == nullptr) {
                    spdlog::info("Bluetooth app registered successfully.");
                    // Only register advertisement after GATT application is fully registered
                    registerAdvertisement();

                    // Wait a bit for advertisement to be processed
                    std::thread([this]() {
                        std::this_thread::sleep_for(std::chrono::seconds(2));
                        if (impl->advertisementRegistered) {
                            spdlog::info("✅ Advertisement is active and device should be visible");
                        } else {
                            spdlog::warn("⚠️ Advertisement registration may have failed");
                        }
                    }).detach();
                } else {
                    spdlog::error("Bluetooth registration error: {} - {}", error->getName(), error->getMessage());
                } });

        impl->ready = true;
        spdlog::info("LinuxBluetooth::initialize completed successfully");
        return true;
    }
    catch (const std::exception &e)
    {
        spdlog::error("LinuxBluetooth::initialize error: {}", e.what());
        impl->ready = false;
        return false;
    }
}

bool LinuxBluetooth::start()
{
    spdlog::info("LinuxBluetooth::start called");

    if (!impl->ready)
    {
        spdlog::warn("LinuxBluetooth not ready, cannot start");
        return false;
    }

    // Check advertisement status
    if (impl->advertisementRegistered && impl->advManager)
    {
        spdlog::info("Advertisement status check:");
        spdlog::info("  ActiveInstances: {}", impl->advManager->ActiveInstances());
        spdlog::info("  Advertisement registered: {}", static_cast<bool>(impl->advertisementRegistered));

        if (impl->advManager->ActiveInstances() > 0)
        {
            spdlog::info("✅ Advertisement is active - device should be visible to scanners");
        }
        else
        {
            spdlog::warn("⚠️ Advertisement not active - device may not be visible");
        }
    }

    // Start scanning for other devices
    startScanning();

    // Enter processing loop async (it will keep DBus running)
    spdlog::info("Entering DBus event loop...");
    impl->connection->enterEventLoopAsync();
    spdlog::info("DBus event loop started");
    return true;
}

void LinuxBluetooth::stop()
{
    impl->ready = false;

    // Stop scanning
    if (impl->scanning)
    {
        try
        {
            if (impl->adapter)
            {
                impl->adapter->StopDiscovery();
                spdlog::info("Discovery stopped");
            }
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error stopping discovery: {}", e.what());
        }
        impl->scanning = false;
    }

    // Clean up connected devices
    {
        std::lock_guard<std::mutex> lock(impl->connectionsMutex);
        impl->connectedDevices.clear();
        impl->deviceClients.clear();
        impl->subscribedClients.clear();
        impl->discoveredDevices.clear();
    }

    // Unregister advertisement if it was registered
    if (impl->advertisementRegistered && impl->advManager)
    {
        try
        {
            // Try to unregister all advertisements to ensure clean state
            // The advertisement will be automatically unregistered when it goes out of scope
            impl->advertisementRegistered = false;
            spdlog::info("Advertisement unregistered.");
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error unregistering advertisement: {}", e.what());
        }
    }

    // Clean up GATT application if registered
    if (impl->app)
    {
        try
        {
            // Unregister GATT application
            auto gattMgr = GattManager1(*impl->connection, "org.bluez", "/org/bluez/hci0");
            gattMgr.UnregisterApplication(impl->app->getPath());
            spdlog::info("GATT application unregistered.");
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error unregistering GATT application: {}", e.what());
        }
    }

    // Clean up connection if it exists
    if (impl->connection)
    {
        try
        {
            impl->connection->leaveEventLoop();
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error leaving event loop: {}", e.what());
        }
    }
}

void LinuxBluetooth::startScanning()
{
    if (!impl->ready)
        return;

    impl->scanning = true;
    spdlog::info("Started scanning for devices...");

    // Start discovery on the adapter
    try
    {
        impl->adapter->StartDiscovery();
        spdlog::info("Discovery started on adapter");

        // Set up device monitoring via D-Bus signals
        setupDeviceMonitoring();
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error starting discovery: {}", e.what());
    }
}

void LinuxBluetooth::setupDeviceMonitoring()
{
    spdlog::info("Setting up DBus signal monitoring for device discovery");

    // Set up DBus signal monitoring for device discovery
    try
    {
        // Monitor for new devices being added to the adapter
        auto proxy = sdbus::createProxy(*impl->connection, "org.bluez", "/");

        // Listen for InterfacesAdded signals
        proxy->uponSignal("InterfacesAdded").onInterface("org.freedesktop.DBus.ObjectManager").call([this](const sdbus::ObjectPath &path, const std::map<std::string, std::map<std::string, sdbus::Variant>> &interfaces)
                                                                                                    {
            // Check if this is a device path (starts with /org/bluez/hci0/dev_)
            if (path.find("/org/bluez/hci0/dev_") == 0) {
                // Check if it has Device1 interface
                auto deviceIface = interfaces.find("org.bluez.Device1");
                if (deviceIface != interfaces.end()) {
                    // Extract device information
                    std::string address = "";
                    std::string name = "";

                    auto addrIt = deviceIface->second.find("Address");
                    if (addrIt != deviceIface->second.end()) {
                        address = addrIt->second.get<std::string>();
                    }

                    auto nameIt = deviceIface->second.find("Name");
                    if (nameIt != deviceIface->second.end()) {
                        name = nameIt->second.get<std::string>();
                    }

                    auto aliasIt = deviceIface->second.find("Alias");
                    if (aliasIt != deviceIface->second.end()) {
                        // Use alias if name is empty
                        if (name.empty()) {
                            name = aliasIt->second.get<std::string>();
                        }
                    }

                    // Only process if we have an address
                    if (!address.empty()) {
                        spdlog::info("New device discovered via DBus signal: {} ({}) at {}", name, address, path);
                        impl->onDeviceFound(path, address, name);

                        // Set up PropertiesChanged monitoring for this specific device
                        this->setupDevicePropertiesMonitoring(path);
                    }
                }
            } });

        // Listen for InterfacesRemoved signals
        proxy->uponSignal("InterfacesRemoved").onInterface("org.freedesktop.DBus.ObjectManager").call([this](const sdbus::ObjectPath &path, const std::vector<std::string> &interfaces)
                                                                                                      {
            // Check if this is a device path and if Device1 interface was removed
            if (path.find("/org/bluez/hci0/dev_") == 0) {
                for (const auto& interface : interfaces) {
                    if (interface == "org.bluez.Device1") {
                        spdlog::info("Device removed via DBus signal: {}", path);
                        this->onDeviceRemoved(path);
                        break;
                    }
                }
            } });

        // Finish registration
        proxy->finishRegistration();

        spdlog::info("DBus signal monitoring set up successfully");
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error setting up DBus signal monitoring: {}", e.what());
    }
}

void LinuxBluetooth::onDeviceRemoved(const std::string &devicePath)
{
    std::lock_guard<std::mutex> lock(impl->connectionsMutex);

    // Check if this device was connected
    for (auto it = impl->connectedDevices.begin(); it != impl->connectedDevices.end(); ++it)
    {
        if (it->second)
        {
            // Try to get the device path - this might not work with the current API
            // For now, we'll just check if the device is still connected
            try
            {
                if (!it->second->Connected())
                {
                    std::string peerId = it->first;
                    spdlog::info("Device disconnected: {}", peerId);

                    // Remove from connected devices
                    impl->connectedDevices.erase(it);
                    impl->deviceClients.erase(peerId);

                    // Notify callback
                    if (impl->peerDisconnectedCallback)
                    {
                        impl->peerDisconnectedCallback(peerId);
                    }
                    break;
                }
            }
            catch (const std::exception &e)
            {
                // If we can't check the connection status, assume it's disconnected
                std::string peerId = it->first;
                spdlog::info("Device appears to be disconnected: {}", peerId);

                impl->connectedDevices.erase(it);
                impl->deviceClients.erase(peerId);

                if (impl->peerDisconnectedCallback)
                {
                    impl->peerDisconnectedCallback(peerId);
                }
                break;
            }
        }
    }

    // Remove from discovered devices
    impl->discoveredDevices.erase(devicePath);
}

bool LinuxBluetooth::sendPacket(const bitchat::BitchatPacket &packet)
{
    if (!impl->ready)
        return false;

    // Serialize C++ packet to raw bytes
    std::vector<uint8_t> data = impl->serializer.serializePacket(packet);

    spdlog::info("LinuxBluetooth::sendPacket sending {} bytes", data.size());

    // Send to all connected devices and subscribed clients
    std::lock_guard<std::mutex> lock(impl->connectionsMutex);

    bool sent = false;

    // Send to all connected devices via our characteristic
    for (auto &devicePair : impl->connectedDevices)
    {
        auto peerId = devicePair.first;
        auto device = devicePair.second;
        auto clientIter = impl->deviceClients.find(peerId);

        if (clientIter != impl->deviceClients.end() && device->Connected())
        {
            try
            {
                // Send via our characteristic to the connected device
                impl->chatCharacteristic->sendNotification(data);
                spdlog::info("Sent packet to device: {}", peerId);
                sent = true;
            }
            catch (const std::exception &e)
            {
                spdlog::error("Error sending to device {}: {}", peerId, e.what());
            }
        }
    }

    // Send to subscribed clients (devices connected to us)
    if (!impl->subscribedClients.empty())
    {
        try
        {
            impl->chatCharacteristic->sendNotification(data);
            spdlog::info("Sent packet to {} subscribed clients", impl->subscribedClients.size());
            sent = true;
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error sending to subscribed clients: {}", e.what());
        }
    }

    if (!sent)
    {
        spdlog::warn("No devices connected or subscribed - packet not sent");
    }

    return sent;
}

bool LinuxBluetooth::sendPacketToPeer(const bitchat::BitchatPacket &packet, const std::string &peerId)
{
    if (!impl->ready)
        return false;

    // Serialize C++ packet to raw bytes
    std::vector<uint8_t> data = impl->serializer.serializePacket(packet);

    spdlog::info("LinuxBluetooth::sendPacketToPeer sending {} bytes to peer: {}", data.size(), peerId);

    std::lock_guard<std::mutex> lock(impl->connectionsMutex);

    // Try to send to connected device
    auto deviceIter = impl->connectedDevices.find(peerId);
    if (deviceIter != impl->connectedDevices.end())
    {
        auto device = deviceIter->second;
        auto clientIter = impl->deviceClients.find(peerId);

        if (clientIter != impl->deviceClients.end() && device->Connected())
        {
            try
            {
                // Send targeted notification to specific peer
                impl->chatCharacteristic->sendNotification(data);
                spdlog::info("Sent packet to specific peer: {}", peerId);
                return true;
            }
            catch (const std::exception &e)
            {
                spdlog::error("Error sending to peer {}: {}", peerId, e.what());
            }
        }
    }

    // Also check subscribed clients for this specific peer
    if (!impl->subscribedClients.empty())
    {
        // This is a simplified check - in a real implementation we would track which client belongs to which peer
        try
        {
            impl->chatCharacteristic->sendNotification(data);
            spdlog::info("Sent packet to subscribed client for peer: {}", peerId);
            return true;
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error sending to subscribed client: {}", e.what());
        }
    }

    spdlog::warn("Peer not found or not connected: {}", peerId);
    return false;
}

bool LinuxBluetooth::isReady() const
{
    return impl->ready;
}

std::string LinuxBluetooth::getLocalPeerId() const
{
    return impl->localPeerId;
}

size_t LinuxBluetooth::getConnectedPeersCount() const
{
    std::lock_guard<std::mutex> lock(impl->connectionsMutex);
    return impl->connectedDevices.size();
}

bool LinuxBluetooth::isAdvertising() const
{
    if (!impl->advManager)
    {
        return false;
    }

    try
    {
        return impl->advManager->ActiveInstances() > 0 && impl->advertisementRegistered;
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error checking advertisement status: {}", e.what());
        return false;
    }
}

std::string LinuxBluetooth::getAdvertisementStatus() const
{
    if (!impl->advManager)
    {
        return "No advertising manager";
    }

    try
    {
        std::string status = "Advertisement Status:\n";
        status += "  ActiveInstances: " + std::to_string(impl->advManager->ActiveInstances()) + "\n";
        status += "  SupportedInstances: " + std::to_string(impl->advManager->SupportedInstances()) + "\n";
        status += "  Registered: " + std::string(static_cast<bool>(impl->advertisementRegistered) ? "Yes" : "No") + "\n";
        status += "  Local Name: " + impl->localPeerId + "\n";
        status += "  Service UUID: " + bitchat::constants::BLE_SERVICE_UUID + "\n";
        return status;
    }
    catch (const std::exception &e)
    {
        return "Error getting advertisement status: " + std::string(e.what());
    }
}

void LinuxBluetooth::setPeerDisconnectedCallback(bitchat::PeerDisconnectedCallback callback)
{
    impl->peerDisconnectedCallback = std::move(callback);
}

void LinuxBluetooth::setPacketReceivedCallback(bitchat::PacketReceivedCallback callback)
{
    impl->packetReceivedCallback = std::move(callback);
}

void LinuxBluetooth::addSubscribedClient(std::shared_ptr<ChatClient> client)
{
    std::lock_guard<std::mutex> lock(impl->connectionsMutex);
    impl->subscribedClients.insert(client);
}

void LinuxBluetooth::removeSubscribedClient(std::shared_ptr<ChatClient> client)
{
    std::lock_guard<std::mutex> lock(impl->connectionsMutex);
    impl->subscribedClients.erase(client);
}

void LinuxBluetooth::setupDevicePropertiesMonitoring(const std::string &devicePath)
{
    try
    {
        // Create a proxy for this specific device to monitor its properties
        auto deviceProxy = sdbus::createProxy(*impl->connection, "org.bluez", devicePath);

        // Listen for PropertiesChanged signals on this device
        deviceProxy->uponSignal("PropertiesChanged").onInterface("org.freedesktop.DBus.Properties").call([this, devicePath](const std::string &interface, const std::map<std::string, sdbus::Variant> &changedProperties, [[maybe_unused]] const std::vector<std::string> &invalidatedProperties)
                                                                                                         {
            // Check if this is a Device1 interface
            if (interface == "org.bluez.Device1") {
                // Check for Connected property changes
                auto connectedIt = changedProperties.find("Connected");
                if (connectedIt != changedProperties.end()) {
                    bool connected = connectedIt->second.get<bool>();
                    spdlog::info("Device {} Connected property changed to: {}", devicePath, connected);

                    if (connected) {
                        this->onDeviceConnected(devicePath);
                    } else {
                        this->onDeviceDisconnected(devicePath);
                    }
                }

                // Check for ServicesResolved property changes
                auto servicesResolvedIt = changedProperties.find("ServicesResolved");
                if (servicesResolvedIt != changedProperties.end()) {
                    bool servicesResolved = servicesResolvedIt->second.get<bool>();
                    spdlog::info("Device {} ServicesResolved property changed to: {}", devicePath, servicesResolved);

                    if (servicesResolved) {
                        this->onDeviceServicesResolved(devicePath);
                    }
                }
            } });

        // Finish registration
        deviceProxy->finishRegistration();

        spdlog::debug("Properties monitoring set up for device: {}", devicePath);
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error setting up properties monitoring for device {}: {}", devicePath, e.what());
    }
}

// New method to handle data received from other devices
void LinuxBluetooth::onDataReceived(const std::vector<uint8_t> &data)
{
    spdlog::info("LinuxBluetooth::onDataReceived received {} bytes", data.size());

    if (data.size() < bitchat::constants::BLE_MIN_PACKET_SIZE_BYTES)
    {
        spdlog::info("Ignoring packet too small: {} bytes", data.size());
        return; // Ignore invalid or too small packets
    }

    try
    {
        // Deserialize the raw data into a BitchatPacket object
        bitchat::BitchatPacket packet = impl->serializer.deserializePacket(data);

        spdlog::info("Successfully deserialized packet of type: {}", (int)packet.type);

        // Forward to the callback if set
        if (impl->packetReceivedCallback)
        {
            impl->packetReceivedCallback(packet);
        }
        else
        {
            spdlog::info("No packet received callback set");
        }
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error deserializing packet: {}", e.what());
    }
}

void LinuxBluetooth::onDeviceConnected(const std::string &devicePath)
{
    spdlog::info("Device connected: {}", devicePath);

    try
    {
        auto device = impl->discoveredDevices[devicePath];
        if (!device)
        {
            spdlog::error("Device not found in discovered devices: {}", devicePath);
            return;
        }

        // Add to connected devices
        std::lock_guard<std::mutex> lock(impl->connectionsMutex);
        std::string peerId = device->Alias().empty() ? device->Address() : device->Alias();
        impl->connectedDevices[peerId] = device;

        spdlog::info("Device {} added to connected devices", peerId);
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error handling device connection for {}: {}", devicePath, e.what());
    }
}

void LinuxBluetooth::onDeviceDisconnected(const std::string &devicePath)
{
    spdlog::info("Device disconnected: {}", devicePath);

    try
    {
        // Find and remove from connected devices
        std::lock_guard<std::mutex> lock(impl->connectionsMutex);

        // Find the device in discoveredDevices to get its peer ID
        auto deviceIt = impl->discoveredDevices.find(devicePath);
        if (deviceIt != impl->discoveredDevices.end())
        {
            std::string peerId = deviceIt->second->Alias().empty() ? deviceIt->second->Address() : deviceIt->second->Alias();

            // Remove from connected devices
            auto connectedIt = impl->connectedDevices.find(peerId);
            if (connectedIt != impl->connectedDevices.end())
            {
                spdlog::info("Removing disconnected device: {}", peerId);

                impl->connectedDevices.erase(connectedIt);
                impl->deviceClients.erase(peerId);

                // Notify callback
                if (impl->peerDisconnectedCallback)
                {
                    impl->peerDisconnectedCallback(peerId);
                }
            }
        }
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error handling device disconnection for {}: {}", devicePath, e.what());
    }
}

void LinuxBluetooth::onDeviceServicesResolved(const std::string &devicePath)
{
    spdlog::info("Device services resolved: {}", devicePath);

    // Now that services are resolved, we can discover them
    impl->discoverServices(devicePath);
}

void LinuxBluetooth::registerAdvertisement()
{
    spdlog::info("=== Starting Advertisement Registration ===");

    // 4. Advertising - Only called after GATT application is fully registered
    impl->advManager = std::make_shared<LEAdvertisingManager1>(impl->connection, "org.bluez", "/org/bluez/hci0");

    // Check if advertising is supported
    spdlog::info("LEAdvertisingManager1");
    spdlog::info("  ActiveInstances: {}", impl->advManager->ActiveInstances());
    spdlog::info("  SupportedInstances: {}", impl->advManager->SupportedInstances());

    // Check supported includes
    try
    {
        auto includes = impl->advManager->SupportedIncludes();
        spdlog::info("  SupportedIncludes: ");
        for (const auto &include : includes)
        {
            spdlog::info("    - {}", include);
        }
    }
    catch (const std::exception &e)
    {
        spdlog::warn("Could not get supported includes: {}", e.what());
    }

    // Wait for any existing advertising to be cleaned up
    if (impl->advManager->ActiveInstances() > 0)
    {
        spdlog::info("Waiting for existing advertising instances to be cleaned up...");
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    // Create advertisement using the correct API pattern from the example
    spdlog::info("Creating advertisement with path: {}", ADV_PATH);
    spdlog::info("Service UUID: {}", bitchat::constants::BLE_SERVICE_UUID);
    spdlog::info("Local name: {}", impl->localPeerId);

    try
    {
        spdlog::info("Creating LEAdvertisement1 object...");

        // Create advertisement with more explicit configuration
        auto ad = LEAdvertisement1::create(*impl->connection, ADV_PATH)
                      .withLocalName(impl->localPeerId)
                      .withServiceUUIDs(std::vector{bitchat::constants::BLE_SERVICE_UUID})
                      .withType("peripheral")
                      .withDiscoverable(true)
                      .withAppearance(0x03C0) // Generic Computer appearance
                      .onReleaseCall([]()
                                     { spdlog::info("advertisement released"); })
                      .registerWith(impl->advManager, [this](const sdbus::Error *error)
                                    {
                if (error == nullptr) {
                    spdlog::info("✅ Advertisement registered successfully.");
                    spdlog::info("✅ Device should now be visible to scanners like nRF Connect");
                    spdlog::info("✅ Device name: {}", impl->localPeerId);
                    spdlog::info("✅ Service UUID: {}", bitchat::constants::BLE_SERVICE_UUID);
                    impl->advertisementRegistered = true;
                } else {
                    spdlog::error("❌ Advertisement registration failed: {} - {}", error->getName(), error->getMessage());
                    impl->advertisementRegistered = false;
                } });

        // Store the advertisement object to prevent it from being destroyed
        impl->advertisement = ad;
        spdlog::info("Advertisement object created and stored");

        // Verify advertisement was created properly
        spdlog::info("Advertisement verification:");
        spdlog::info("  Path: {}", impl->advertisement->getPath());
    }
    catch (const std::exception &e)
    {
        spdlog::error("❌ Exception during advertisement creation: {}", e.what());
        impl->advertisementRegistered = false;
    }

    spdlog::info("=== Advertisement Registration Process Complete ===");
}
