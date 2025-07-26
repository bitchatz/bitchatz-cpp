#include "bitchat/services/network_service.h"
#include "bitchat/core/bitchat_data.h"
#include "bitchat/core/constants.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/protocol_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/protocol/packet_serializer.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
#include <algorithm>
#include <chrono>
#include <ranges>
#include <spdlog/spdlog.h>

namespace bitchat
{

NetworkService::NetworkService()
{
    // Pass
}

NetworkService::~NetworkService()
{
    stop();
}

bool NetworkService::initialize(std::shared_ptr<IBluetoothNetwork> bluetoothNetworkInterface, std::shared_ptr<BluetoothAnnounceRunner> announceRunner, std::shared_ptr<CleanupRunner> cleanupRunner)
{
    // Set Bluetooth network interface
    this->bluetoothNetworkInterface = bluetoothNetworkInterface;

    if (!bluetoothNetworkInterface)
    {
        spdlog::error("NetworkService: Bluetooth interface is null");
        return false;
    }

    // Set runners
    this->announceRunner = announceRunner;
    this->cleanupRunner = cleanupRunner;

    // Set up Bluetooth network callbacks
    // clang-format off
    bluetoothNetworkInterface->setPacketReceivedCallback([this](const BitchatPacket &packet, const std::string &peripheralID) {
        onPacketReceived(packet, peripheralID);
    });
    // clang-format on

    // clang-format off
    bluetoothNetworkInterface->setPeerConnectedCallback([this](const std::string &peripheralID) {
        onPeerConnected(peripheralID);
    });
    // clang-format on

    // clang-format off
    bluetoothNetworkInterface->setPeerDisconnectedCallback([this](const std::string &peripheralID) {
        onPeerDisconnected(peripheralID);
    });
    // clang-format on

    // Initialize runners
    if (announceRunner)
    {
        announceRunner->setBluetoothNetworkInterface(bluetoothNetworkInterface);
    }

    spdlog::info("NetworkService initialized");

    return true;
}

bool NetworkService::start()
{
    if (!bluetoothNetworkInterface)
    {
        spdlog::error("NetworkService: Cannot start without Bluetooth network interface");
        return false;
    }

    if (!bluetoothNetworkInterface->initialize())
    {
        spdlog::error("NetworkService: Failed to initialize Bluetooth network interface");
        return false;
    }

    if (!bluetoothNetworkInterface->start())
    {
        spdlog::error("NetworkService: Failed to start Bluetooth network interface");
        return false;
    }

    // Start runners
    if (announceRunner)
    {
        announceRunner->start();
    }

    if (cleanupRunner)
    {
        cleanupRunner->start();
    }

    spdlog::info("NetworkService started");

    return true;
}

void NetworkService::stop()
{
    if (announceRunner)
    {
        announceRunner->stop();
    }

    if (cleanupRunner)
    {
        cleanupRunner->stop();
    }

    if (bluetoothNetworkInterface)
    {
        bluetoothNetworkInterface->stop();
    }

    spdlog::info("NetworkService stopped");
}

bool NetworkService::sendPacket(const BitchatPacket &packet)
{
    if (!bluetoothNetworkInterface)
    {
        return false;
    }

    return bluetoothNetworkInterface->sendPacket(packet);
}

bool NetworkService::sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID)
{
    if (!bluetoothNetworkInterface)
    {
        return false;
    }

    return bluetoothNetworkInterface->sendPacketToPeer(packet, peerID);
}

void NetworkService::setPacketReceivedCallback(PacketReceivedCallback callback)
{
    packetReceivedCallback = callback;
}

void NetworkService::setPeerConnectedCallback(PeerConnectedCallback callback)
{
    peerConnectedCallback = callback;
}

void NetworkService::setPeerDisconnectedCallback(PeerDisconnectedCallback callback)
{
    peerDisconnectedCallback = callback;
}

void NetworkService::onPeerConnected(const std::string &peripheralID)
{
    spdlog::info("Peer connected with UUID: {}", peripheralID);

    if (peerConnectedCallback)
    {
        peerConnectedCallback(peripheralID);
    }
}

void NetworkService::onPeerDisconnected(const std::string &peripheralID)
{
    spdlog::info("Peer disconnected with UUID: {}", peripheralID);

    if (peerDisconnectedCallback)
    {
        peerDisconnectedCallback(peripheralID);
    }
}

void NetworkService::onPacketReceived(const BitchatPacket &packet, const std::string &peripheralID)
{
    // Delegate all packet processing to MessageService via callback
    if (packetReceivedCallback)
    {
        packetReceivedCallback(packet, peripheralID);
    }

    // Relay packet if needed (this is still handled by NetworkService)
    if (packet.getTTL() > 0)
    {
        relayPacket(packet);
    }
}

void NetworkService::relayPacket(const BitchatPacket &packet)
{
    // Create relay packet with decremented TTL
    BitchatPacket relayPacket = packet;
    relayPacket.setTTL(packet.getTTL() - 1);

    // Send to all connected peers except sender
    std::string senderID = StringHelper::toHex(packet.getSenderID());

    auto peers = BitchatData::shared()->getPeers();
    for (const auto &peer : peers)
    {
        if (peer.getPeerID() != senderID)
        {
            bluetoothNetworkInterface->sendPacketToPeer(relayPacket, peer.getPeerID());
        }
    }
}

void NetworkService::setBluetoothNetworkInterface(std::shared_ptr<IBluetoothNetwork> bluetoothNetworkInterface)
{
    this->bluetoothNetworkInterface = bluetoothNetworkInterface;
}

} // namespace bitchat
