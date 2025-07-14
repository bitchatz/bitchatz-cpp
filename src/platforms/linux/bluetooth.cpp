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

// RemoteCharacteristic wrapper class to handle remote characteristics
class RemoteCharacteristic
{
public:
    RemoteCharacteristic(std::shared_ptr<sdbus::IConnection> connection, const std::string &path)
        : connection(connection)
        , path(path)
    {
    }

    bool writeValue(const std::vector<uint8_t> &data)
    {
        try
        {
            // Use DBus directly to write to the characteristic
            auto proxy = sdbus::createProxy(*connection, "org.bluez", path);
            proxy->callMethod("WriteValue")
                .onInterface("org.bluez.GattCharacteristic1")
                .withArguments(data, std::map<std::string, sdbus::Variant>{});
            return true;
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error writing to remote characteristic: {}", e.what());
            return false;
        }
    }

    bool startNotify()
    {
        try
        {
            auto proxy = sdbus::createProxy(*connection, "org.bluez", path);
            proxy->callMethod("StartNotify")
                .onInterface("org.bluez.GattCharacteristic1")
                .withArguments(std::map<std::string, sdbus::Variant>{});
            return true;
        }
        catch (const std::exception &e)
        {
            spdlog::info("Could not start notify (this is normal): {}", e.what());
            return false;
        }
    }

private:
    std::shared_ptr<sdbus::IConnection> connection;
    std::string path;
};

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
class ChatCharacteristic : public GattCharacteristicBuilder<GenericCharacteristic>
{
public:
    ChatCharacteristic(std::shared_ptr<GattService1> service,
                       std::shared_ptr<sdbus::IConnection> connection,
                       std::string uuid,
                       LinuxBluetooth *bluetooth)
        : GattCharacteristicBuilder{std::move(service), std::move(uuid), true, true, true, false}
        , connection{std::move(connection)}
        , bluetooth(bluetooth)
    {
        // Flags are set in the constructor of GattCharacteristicBuilder
        // Parameters: service, uuid, read, write, notify, indicate
    }

    static std::shared_ptr<ChatCharacteristic> create(std::shared_ptr<GattService1> service,
                                                      std::shared_ptr<sdbus::IConnection> connection,
                                                      std::string uuid,
                                                      LinuxBluetooth *bluetooth)
    {
        return std::shared_ptr<ChatCharacteristic>(new ChatCharacteristic(std::move(service), std::move(connection), std::move(uuid), bluetooth));
    }

    // Public method to send notifications
    void sendNotification(const std::vector<uint8_t> &data)
    {
        // Send to all subscribed clients
        for (auto &client : clients)
        {
            directedQueue.insert(std::make_pair(client.first, std::vector<std::vector<uint8_t>>{data}));
        }
        if (!clients.empty())
        {
            emitPropertyChangedSignal("DirectedValue");
        }
    }

protected:
    virtual std::vector<uint8_t> ReadValue(const std::map<std::string, sdbus::Variant> &options) override
    {
        // Return current value for read operations
        auto client = getClient(options);
        return client->getDataRef();
    }

    virtual void WriteValue(const std::vector<uint8_t> &value, const std::map<std::string, sdbus::Variant> &options) override
    {
        // Process incoming data - this is where we receive packets from other devices
        auto client = getClient(options);
        client->setData(value);

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
        auto client = getClient(options);
        spdlog::info("ChatCharacteristic::StartNotify '{}'", client->getPath());

        // Add to subscribed clients
        if (bluetooth)
        {
            bluetooth->addSubscribedClient(client);
        }
    }

    void StopNotify(const std::map<std::string, sdbus::Variant> &options) override
    {
        if (options.size() != 0)
        {
            auto client = getClient(options);
            spdlog::info("ChatCharacteristic::StopNotify '{}'", client->getPath());

            // Remove from subscribed clients
            if (bluetooth)
            {
                bluetooth->removeSubscribedClient(client);
            }
        }
    }

    std::map<sdbus::ObjectPath, std::vector<std::vector<uint8_t>>> DirectedValue() override
    {
        return std::move(directedQueue);
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

    std::map<sdbus::ObjectPath, std::vector<std::vector<uint8_t>>> directedQueue;
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

    // Collections for managing BLE connections (equivalent to Objective-C)
    std::map<std::string, std::shared_ptr<Device1>> connectedDevices;                   // Connected devices
    std::map<std::string, std::shared_ptr<ChatClient>> deviceClients;                   // Clients for each device
    std::set<std::shared_ptr<ChatClient>> subscribedClients;                            // Subscribed clients
    std::map<std::string, std::shared_ptr<Device1>> discoveredDevices;                  // Discovered devices
    std::map<std::string, std::shared_ptr<RemoteCharacteristic>> remoteCharacteristics; // ADD: Remote characteristics for Central role
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

            // Set up connection monitoring
            monitorDeviceConnection(devicePath);
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error connecting to device {}: {}", devicePath, e.what());
        }
    }

    void monitorDeviceConnection(const std::string &devicePath)
    {
        // Start a thread to monitor the device connection status
        std::thread([this, devicePath]()
                    {
            try {
                auto device = discoveredDevices[devicePath];
                
                // Wait for connection to be established
                int attempts = 0;
                const int maxAttempts = 50; // 5 seconds timeout
                
                while (attempts < maxAttempts && scanning && ready) {
                    try {
                        if (device->Connected()) {
                            spdlog::info("Device connected: {}", devicePath);
                            
                            // Add to connected devices
                            std::lock_guard<std::mutex> lock(connectionsMutex);
                            std::string peerId = device->Alias().empty() ? device->Address() : device->Alias();
                            connectedDevices[peerId] = device;
                            
                            // Discover services
                            discoverServices(devicePath);
                            return; // Success, exit thread
                        }
                    } catch (const std::exception& e) {
                        spdlog::debug("Error checking connection status: {}", e.what());
                    }
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    attempts++;
                }
                
                if (attempts >= maxAttempts) {
                    spdlog::warn("Connection timeout for device: {}", devicePath);
                } else if (!scanning || !ready) {
                    spdlog::info("Connection monitoring stopped for device: {}", devicePath);
                }
                
            } catch (const std::exception& e) {
                spdlog::error("Error monitoring device connection for {}: {}", devicePath, e.what());
            } })
            .detach();
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
                // Wait a bit and try again
                std::thread([this, devicePath]()
                            {
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                    discoverServices(devicePath); })
                    .detach();
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
                spdlog::info("Device has our service, discovering characteristics...");

                // Discover remote characteristics from peer via DBus
                try
                {
                    // Use DBus directly to get managed objects
                    auto proxy = sdbus::createProxy(*connection, "org.bluez", "/");
                    std::map<sdbus::ObjectPath, std::map<std::string, std::map<std::string, sdbus::Variant>>> objects;
                    proxy->callMethod("GetManagedObjects")
                        .onInterface("org.freedesktop.DBus.ObjectManager")
                        .storeResultsTo(objects);

                    for (const auto &[path, ifaces] : objects)
                    {
                        // Ensure it's a child of the device
                        if (path.find(devicePath) == 0)
                        {
                            auto charIface = ifaces.find("org.bluez.GattCharacteristic1");
                            if (charIface != ifaces.end())
                            {
                                auto uuidIt = charIface->second.find("UUID");
                                if (uuidIt != charIface->second.end())
                                {
                                    try
                                    {
                                        auto uuid = uuidIt->second.get<std::string>();
                                        if (uuid == bitchat::constants::BLE_CHARACTERISTIC_UUID)
                                        {
                                            // Found the correct characteristic!
                                            auto remoteChar = std::make_shared<RemoteCharacteristic>(connection, path);
                                            remoteCharacteristics[devicePath] = remoteChar;

                                            // Try to start notifications
                                            if (remoteChar->startNotify())
                                            {
                                                spdlog::info("Discovered and subscribed to remote characteristic at: {}", path);
                                            }
                                            else
                                            {
                                                spdlog::info("Discovered remote characteristic at: {} (notifications not available)", path);
                                            }
                                            break; // Found our characteristic, no need to continue
                                        }
                                    }
                                    catch (const std::exception &e)
                                    {
                                        spdlog::debug("Error getting UUID from characteristic: {}", e.what());
                                        continue;
                                    }
                                }
                            }
                        }
                    }

                    if (remoteCharacteristics.find(devicePath) == remoteCharacteristics.end())
                    {
                        spdlog::warn("Could not find remote characteristic for device: {}", devicePath);
                    }
                }
                catch (const std::exception &e)
                {
                    spdlog::error("Error discovering remote characteristics via DBus: {}", e.what());
                    // Continue with normal setup even if characteristic discovery fails
                }

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

        impl->adapter->Discoverable(true);
        impl->adapter->Pairable(true);
        impl->adapter->Alias(impl->localPeerId);

        spdlog::info("Adapter configured:");
        spdlog::info("  Name: {}", impl->adapter->Name());
        spdlog::info("  Address: {}", impl->adapter->Address());
        spdlog::info("  Powered: {}", impl->adapter->Powered());
        spdlog::info("  Discoverable: {}", impl->adapter->Discoverable());
        spdlog::info("  Pairable: {}", impl->adapter->Pairable());

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
        spdlog::info("GATT characteristic created");

        impl->chatCharacteristic->finalize();
        spdlog::info("GATT characteristic finalized");

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
                } else {
                    spdlog::error("Bluetooth registration error: {}", error->getMessage());
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
        impl->remoteCharacteristics.clear();
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

        // Set up device monitoring
        setupDeviceMonitoring();

        // Set up a timer to stop discovery after a while and restart it
        // This helps with device discovery
        std::thread([this]()
                    {
            while (impl->scanning && impl->ready) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                
                try {
                    // Stop and restart discovery periodically
                    impl->adapter->StopDiscovery();
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    impl->adapter->StartDiscovery();
                    spdlog::info("Discovery restarted");
                } catch (const std::exception& e) {
                    spdlog::error("Error restarting discovery: {}", e.what());
                }
            } })
            .detach();
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error starting discovery: {}", e.what());
    }
}

void LinuxBluetooth::setupDeviceMonitoring()
{
    spdlog::info("Device monitoring set up with polling");

    // Start a thread to periodically check for new devices
    std::thread([this]()
                {
        while (impl->scanning && impl->ready) {
            try {
                // Poll for new devices by scanning /org/bluez/hci0/dev_*
                auto proxy = sdbus::createProxy(*impl->connection, "org.bluez", "/");
                std::map<sdbus::ObjectPath, std::map<std::string, std::map<std::string, sdbus::Variant>>> objects;
                
                proxy->callMethod("GetManagedObjects")
                     .onInterface("org.freedesktop.DBus.ObjectManager")
                     .storeResultsTo(objects);

                for (const auto& [path, interfaces] : objects) {
                    // Check if this is a device path (starts with /org/bluez/hci0/dev_)
                    if (path.find("/org/bluez/hci0/dev_") == 0) {
                        // Check if we already know this device
                        if (impl->discoveredDevices.count(path) == 0) {
                            try {
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
                                        spdlog::info("Found new device: {} ({}) at {}", name, address, path);
                                        impl->onDeviceFound(path, address, name);
                                    }
                                }
                            } catch (const std::exception& e) {
                                spdlog::debug("Error processing device {}: {}", path, e.what());
                                // Continue with next device
                            }
                        }
                    }
                }

                std::this_thread::sleep_for(std::chrono::seconds(2));
                
                // Periodically clean up disconnected devices
                static int cleanupCounter = 0;
                if (++cleanupCounter >= 15) { // Every 30 seconds (15 * 2 seconds)
                    cleanupCounter = 0;
                    // Note: cleanupDisconnectedDevices() is called from the main class
                    // This is handled by the main monitoring loop
                }
            } catch (const std::exception& e) {
                spdlog::error("Error in device monitoring: {}", e.what());
                std::this_thread::sleep_for(std::chrono::seconds(5)); // Longer delay on error
            }
        } })
        .detach();
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

    // Remove from remote characteristics
    impl->remoteCharacteristics.erase(devicePath);
}

void LinuxBluetooth::cleanupDisconnectedDevices()
{
    std::lock_guard<std::mutex> lock(impl->connectionsMutex);

    // Check connected devices
    for (auto it = impl->connectedDevices.begin(); it != impl->connectedDevices.end();)
    {
        try
        {
            if (!it->second->Connected())
            {
                std::string peerId = it->first;
                spdlog::info("Cleaning up disconnected device: {}", peerId);

                // Remove from connected devices
                it = impl->connectedDevices.erase(it);
                impl->deviceClients.erase(peerId);

                // Notify callback
                if (impl->peerDisconnectedCallback)
                {
                    impl->peerDisconnectedCallback(peerId);
                }
            }
            else
            {
                ++it;
            }
        }
        catch (const std::exception &e)
        {
            // If we can't check the connection status, assume it's disconnected
            std::string peerId = it->first;
            spdlog::info("Cleaning up device that appears disconnected: {}", peerId);

            it = impl->connectedDevices.erase(it);
            impl->deviceClients.erase(peerId);

            if (impl->peerDisconnectedCallback)
            {
                impl->peerDisconnectedCallback(peerId);
            }
        }
    }

    // Clean up discovered devices that are no longer available
    for (auto it = impl->discoveredDevices.begin(); it != impl->discoveredDevices.end();)
    {
        try
        {
            // Try to access the device to see if it still exists
            it->second->Address(); // This will throw if device is gone
            ++it;
        }
        catch (const std::exception &e)
        {
            spdlog::debug("Removing unavailable discovered device: {}", it->first);
            it = impl->discoveredDevices.erase(it);
        }
    }
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

    // Send to all remote characteristics
    for (const auto &rc : impl->remoteCharacteristics)
    {
        try
        {
            if (rc.second->writeValue(data))
            {
                spdlog::info("Sent packet via remote characteristic to device: {}", rc.first);
                sent = true;
            }
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error sending to remote characteristic {}: {}", rc.first, e.what());
        }
    }

    // Send to all connected devices (old method as fallback)
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
                spdlog::info("Sent packet to device (fallback): {}", peerId);
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
        impl->chatCharacteristic->sendNotification(data);
        spdlog::info("Sent packet to {} subscribed clients", impl->subscribedClients.size());
        sent = true;
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

    // Send via remote characteristic of the peer
    // First, try to find the device path for this peer
    std::string devicePath;
    for (const auto &devicePair : impl->connectedDevices)
    {
        if (devicePair.first == peerId)
        {
            // Find the corresponding device path
            for (const auto &discoveredPair : impl->discoveredDevices)
            {
                if (discoveredPair.second == devicePair.second)
                {
                    devicePath = discoveredPair.first;
                    break;
                }
            }
            break;
        }
    }

    // If found the device path, try to send via remote characteristic
    if (!devicePath.empty())
    {
        auto it = impl->remoteCharacteristics.find(devicePath);
        if (it != impl->remoteCharacteristics.end())
        {
            try
            {
                if (it->second->writeValue(data))
                {
                    spdlog::info("Sent packet via remote characteristic to peer: {}", peerId);
                    return true;
                }
            }
            catch (const std::exception &e)
            {
                spdlog::error("Error sending to remote characteristic: {}", e.what());
            }
        }
    }

    // Fallback: try old method (for compatibility)
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
                spdlog::info("Sent packet to specific peer (fallback): {}", peerId);
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

void LinuxBluetooth::registerAdvertisement()
{
    // 4. Advertising - Only called after GATT application is fully registered
    impl->advManager = std::make_shared<LEAdvertisingManager1>(impl->connection, "org.bluez", "/org/bluez/hci0");

    // Check if advertising is supported
    spdlog::info("LEAdvertisingManager1");
    spdlog::info("  ActiveInstances: {}", impl->advManager->ActiveInstances());
    spdlog::info("  SupportedInstances: {}", impl->advManager->SupportedInstances());

    // Wait for any existing advertising to be cleaned up
    if (impl->advManager->ActiveInstances() > 0)
    {
        spdlog::info("Waiting for existing advertising instances to be cleaned up...");
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    // Create advertisement using the builder pattern and register it
    // Use unique path with timestamp to avoid conflicts
    std::string uniqueAdvPath = std::string(ADV_PATH) + "_" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());

    spdlog::info("Creating advertisement with path: {}", uniqueAdvPath);
    spdlog::info("Service UUID: {}", bitchat::constants::BLE_SERVICE_UUID);
    spdlog::info("Local name: {}", impl->localPeerId);

    // Try minimal advertising configuration
    try
    {
        LEAdvertisement1::create(*impl->connection, uniqueAdvPath)
            .withLocalName(impl->localPeerId)
            .withServiceUUIDs(std::vector{bitchat::constants::BLE_SERVICE_UUID})
            .withType("peripheral")
            .onReleaseCall([]()
                           { spdlog::info("advertisement released"); })
            .registerWith(impl->advManager, [this](const sdbus::Error *error)
                          {
                if (error == nullptr) {
                    spdlog::info("Advertisement registered successfully.");
                    impl->advertisementRegistered = true;
                } else {
                    spdlog::error("Advertisement registration failed: {} - {}", error->getName(), error->getMessage());
                    impl->advertisementRegistered = false;
                } });
    }
    catch (const std::exception &e)
    {
        spdlog::error("Exception during advertisement creation: {}", e.what());
        impl->advertisementRegistered = false;
    }
}
