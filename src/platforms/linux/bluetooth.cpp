#include "platforms/linux/bluetooth.h"
#include <iostream>

namespace bitchat
{

LinuxBluetooth::LinuxBluetooth()
    : ready(false)
{
    localPeerId = generatePeerId();
}

LinuxBluetooth::~LinuxBluetooth()
{
    stop();
}

bool LinuxBluetooth::initialize()
{
    std::lock_guard<std::mutex> lock(mutex);
    adapter = bluez::Adapter::get_first_adapter();
    if (!adapter)
    {
        std::cerr << "[LinuxBluetooth] No BLE adapter found!" << std::endl;
        return false;
    }

    setupPeripheral();
    setupCentral();

    ready = true;
    return true;
}

bool LinuxBluetooth::start()
{
    std::lock_guard<std::mutex> lock(mutex);
    if (!ready)
        return false;

    if (peripheral)
        peripheral->start_advertising();
    if (central)
        central->start_discovery();

    return true;
}

void LinuxBluetooth::stop()
{
    std::lock_guard<std::mutex> lock(mutex);
    if (peripheral)
        peripheral->stop_advertising();
    if (central)
        central->stop_discovery();
    ready = false;
}

void LinuxBluetooth::setPeerDisconnectedCallback(PeerDisconnectedCallback cb)
{
    std::lock_guard<std::mutex> lock(mutex);
    peerDisconnectedCallback = cb;
}

void LinuxBluetooth::setPacketReceivedCallback(PacketReceivedCallback cb)
{
    std::lock_guard<std::mutex> lock(mutex);
    packetReceivedCallback = cb;
}

bool LinuxBluetooth::sendPacket(const BitchatPacket &packet)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (!ready)
        return false;
    std::vector<uint8_t> data = serializer.serializePacket(packet);

    for (auto &kv : connectedPeripherals)
    {
        auto characteristicPtr = peripheralCharacteristics[kv.first];
        if (characteristicPtr)
        {
            kv.second->write_characteristic(characteristicPtr, data);
        }
    }
    if (characteristic && !subscribedCentrals.empty())
    {
        characteristic->notify(data);
    }
    return true;
}

bool LinuxBluetooth::sendPacketToPeer(const BitchatPacket &packet, const std::string &peerId)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (!ready)
        return false;
    auto it = connectedPeripherals.find(peerId);
    if (it == connectedPeripherals.end())
        return false;
    auto characteristicPtr = peripheralCharacteristics[peerId];
    if (characteristicPtr)
    {
        std::vector<uint8_t> data = serializer.serializePacket(packet);
        it->second->write_characteristic(characteristicPtr, data);
        return true;
    }
    return false;
}

bool LinuxBluetooth::isReady() const
{
    std::lock_guard<std::mutex> lock(mutex);
    return ready;
}

std::string LinuxBluetooth::getLocalPeerId() const
{
    std::lock_guard<std::mutex> lock(mutex);
    return localPeerId;
}

size_t LinuxBluetooth::getConnectedPeersCount() const
{
    std::lock_guard<std::mutex> lock(mutex);
    return connectedPeripherals.size();
}

std::string LinuxBluetooth::generatePeerId()
{
    std::stringstream ss;
    std::random_device rd;
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < bitchat::constants::BLE_PEER_ID_LENGTH_CHARS / 2; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << dis(rd);
    return ss.str();
}

void LinuxBluetooth::setupPeripheral()
{
    peripheral = std::make_shared<bluez::Peripheral>(adapter);

    service = std::make_shared<bluez::GattService>(
        bitchat::constants::BLE_SERVICE_UUID, true);

    characteristic = std::make_shared<bluez::GattCharacteristic>(
        bitchat::constants::BLE_CHARACTERISTIC_UUID,
        bluez::GattCharacteristic::Property::Read |
            bluez::GattCharacteristic::Property::Write |
            bluez::GattCharacteristic::Property::Notify,
        bluez::GattCharacteristic::Permission::Read |
            bluez::GattCharacteristic::Permission::Write);

    characteristic->set_write_callback([this](const std::vector<uint8_t> &value)
                                       {
        if (packetReceivedCallback && value.size() >= bitchat::constants::BLE_MIN_PACKET_SIZE_BYTES) {
            BitchatPacket packet = serializer.deserializePacket(value);
            packetReceivedCallback(packet);
        } });

    characteristic->set_subscribe_callback([this](const std::string &device)
                                           {
        std::lock_guard<std::mutex> lock(mutex);
        if (std::find(subscribedCentrals.begin(), subscribedCentrals.end(), device) == subscribedCentrals.end()) {
            subscribedCentrals.push_back(device);
        } });
    characteristic->set_unsubscribe_callback([this](const std::string &device)
                                             {
        std::lock_guard<std::mutex> lock(mutex);
        subscribedCentrals.erase(
            std::remove(subscribedCentrals.begin(), subscribedCentrals.end(), device),
            subscribedCentrals.end()); });

    service->add_characteristic(characteristic);
    peripheral->add_service(service);
}

void LinuxBluetooth::setupCentral()
{
    central = std::make_shared<bluez::Central>(adapter);

    central->set_device_discovered_callback([this](std::shared_ptr<bluez::Peripheral> peer)
                                            {
        std::string peerId = peer->get_address();
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (connectedPeripherals.count(peerId)) return;
            connectedPeripherals[peerId] = peer;
        }

        peer->connect();
        peer->discover_services([this, peer, peerId](const std::vector<std::shared_ptr<bluez::GattService>>& services) {
            for (const auto& svc : services) {
                if (svc->get_uuid() == bitchat::constants::BLE_SERVICE_UUID) {
                    auto chars = svc->get_characteristics();
                    for (const auto& chr : chars) {
                        if (chr->get_uuid() == bitchat::constants::BLE_CHARACTERISTIC_UUID) {
                            {
                                std::lock_guard<std::mutex> lock(mutex);
                                peripheralCharacteristics[peerId] = chr;
                            }
                            chr->subscribe([this](const std::vector<uint8_t>& value) {
                                if (packetReceivedCallback && value.size() >= bitchat::constants::BLE_MIN_PACKET_SIZE_BYTES) {
                                    BitchatPacket packet = serializer.deserializePacket(value);
                                    packetReceivedCallback(packet);
                                }
                            });
                        }
                    }
                }
            }
        });

        peer->set_disconnect_callback([this, peerId]() {
            {
                std::lock_guard<std::mutex> lock(mutex);
                connectedPeripherals.erase(peerId);
                peripheralCharacteristics.erase(peerId);
            }
            if (peerDisconnectedCallback) peerDisconnectedCallback(peerId);
        }); });
}

} // namespace bitchat
