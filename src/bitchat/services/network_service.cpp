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
    : shouldExit(false)
{
}

NetworkService::~NetworkService()
{
    stop();
}

bool NetworkService::initialize(std::shared_ptr<BluetoothInterface> bluetooth)
{
    bluetoothInterface = bluetooth;

    if (!bluetoothInterface)
    {
        spdlog::error("NetworkService: Bluetooth interface is null");
        return false;
    }

    // Set up Bluetooth callbacks
    // clang-format off
    bluetoothInterface->setPacketReceivedCallback([this](const BitchatPacket &packet, const std::string &peripheralID) {
        onPacketReceived(packet, peripheralID);
    });
    // clang-format on

    // clang-format off
    bluetoothInterface->setPeerConnectedCallback([this](const std::string &peripheralID) {
        onPeerConnected(peripheralID);
    });
    // clang-format on

    // clang-format off
    bluetoothInterface->setPeerDisconnectedCallback([this](const std::string &peripheralID) {
        onPeerDisconnected(peripheralID);
    });
    // clang-format on

    // Initialize runners
    if (announceRunner)
    {
        announceRunner->setBluetoothInterface(bluetoothInterface);
    }

    spdlog::info("NetworkService initialized");

    return true;
}

bool NetworkService::start()
{
    if (!bluetoothInterface)
    {
        spdlog::error("NetworkService: Cannot start without Bluetooth interface");
        return false;
    }

    if (!bluetoothInterface->initialize())
    {
        spdlog::error("NetworkService: Failed to initialize Bluetooth interface");
        return false;
    }

    if (!bluetoothInterface->start())
    {
        spdlog::error("NetworkService: Failed to start Bluetooth interface");
        return false;
    }

    shouldExit = false;

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
    shouldExit = true;

    // Stop runners
    if (announceRunner)
    {
        announceRunner->stop();
    }

    if (cleanupRunner)
    {
        cleanupRunner->stop();
    }

    if (bluetoothInterface)
    {
        bluetoothInterface->stop();
    }

    spdlog::info("NetworkService stopped");
}

bool NetworkService::sendPacket(const BitchatPacket &packet)
{
    if (!bluetoothInterface || !isReady())
    {
        return false;
    }

    return bluetoothInterface->sendPacket(packet);
}

bool NetworkService::sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID)
{
    if (!bluetoothInterface || !isReady())
    {
        return false;
    }

    return bluetoothInterface->sendPacketToPeer(packet, peerID);
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

bool NetworkService::isReady() const
{
    return bluetoothInterface && bluetoothInterface->isReady();
}

void NetworkService::setAnnounceRunner(std::shared_ptr<BluetoothAnnounceRunner> runner)
{
    announceRunner = runner;
}

void NetworkService::setCleanupRunner(std::shared_ptr<CleanupRunner> runner)
{
    cleanupRunner = runner;
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
    auto peers = BitchatData::shared()->getPeers();
    for (const auto &peer : peers)
    {
        if (peer.getPeripheralID() == peripheralID)
        {
            std::string peerID = peer.getPeerID();
            std::string nickname = peer.getNickname();
            BitchatData::shared()->removePeer(peerID);

            spdlog::info("Peer disconnected with UUID: {} ({})", peripheralID, nickname);

            if (peerDisconnectedCallback)
            {
                peerDisconnectedCallback(peerID, nickname);
            }
            break;
        }
    }
}

void NetworkService::onPacketReceived(const BitchatPacket &packet, const std::string &peripheralID)
{
    processPacket(packet, peripheralID);
}

void NetworkService::processPacket(const BitchatPacket &packet, const std::string &peripheralID)
{
    // Validate packet
    if (!packet.isValid())
    {
        spdlog::warn("Received invalid packet from {}", StringHelper::toHex(packet.getSenderID()));
        return;
    }

    // Check if we've already processed this message
    std::string messageID = StringHelper::toHex(packet.getSenderID()) + "_" + std::to_string(packet.getTimestamp());

    if (BitchatData::shared()->wasMessageProcessed(messageID))
    {
        return;
    }

    BitchatData::shared()->markMessageProcessed(messageID);

    // Process based on packet type
    switch (packet.getType())
    {
    case PKT_TYPE_ANNOUNCE:
        processAnnouncePacket(packet, peripheralID);
        break;
    case PKT_TYPE_MESSAGE:
        spdlog::debug("Received MESSAGE packet from {}", StringHelper::toHex(packet.getSenderID()));
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet, peripheralID);
        }
        break;
    case PKT_TYPE_LEAVE:
        spdlog::debug("Received LEAVE packet from {}", StringHelper::toHex(packet.getSenderID()));
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet, peripheralID);
        }
        break;
    case PKT_TYPE_NOISE_HANDSHAKE_INIT:
        spdlog::info("Received NOISE_HANDSHAKE_INIT from {} (payload size: {})", StringHelper::toHex(packet.getSenderID()), packet.getPayload().size());
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet, peripheralID);
        }
        break;
    case PKT_TYPE_NOISE_HANDSHAKE_RESP:
        spdlog::info("Received NOISE_HANDSHAKE_RESP from {}", StringHelper::toHex(packet.getSenderID()));
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet, peripheralID);
        }
        break;
    case PKT_TYPE_NOISE_ENCRYPTED:
        spdlog::info("Received NOISE_ENCRYPTED from {}", StringHelper::toHex(packet.getSenderID()));
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet, peripheralID);
        }
        break;
    case PKT_TYPE_NOISE_IDENTITY_ANNOUNCE:
        spdlog::info("Received NOISE_IDENTITY_ANNOUNCE from {}", StringHelper::toHex(packet.getSenderID()));
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet, peripheralID);
        }
        break;
    default:
        spdlog::debug("Received packet type: {}", packet.getTypeString());
        break;
    }

    // Relay packet if needed
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
            bluetoothInterface->sendPacketToPeer(relayPacket, peer.getPeerID());
        }
    }
}

void NetworkService::processAnnouncePacket(const BitchatPacket &packet, const std::string &peripheralID)
{
    try
    {
        PacketSerializer serializer;
        std::string nickname;
        serializer.parseAnnouncePayload(packet.getPayload(), nickname);

        std::string peerID = StringHelper::toHex(packet.getSenderID());

        // Check if peer is already in the list
        auto existingPeer = BitchatData::shared()->getPeerInfo(peerID);
        if (existingPeer)
        {
            // Update existing peer
            BitchatPeer updatedPeer = *existingPeer;
            updatedPeer.updateLastSeen();

            if (!peripheralID.empty())
            {
                updatedPeer.setPeripheralID(peripheralID);
            }

            BitchatData::shared()->updatePeer(updatedPeer);

            spdlog::debug("Updated existing peer: {} ({})", peerID, nickname);

            return;
        }
        else
        {
            // Add new peer
            BitchatPeer peer(StringHelper::toHex(packet.getSenderID()), nickname);
            peer.updateLastSeen();
            peer.setPeripheralID(peripheralID);
            BitchatData::shared()->addPeer(peer);
        }

        // Notify about new peer connection
        onPeerConnected(peerID);

        spdlog::debug("Processed announce from: {} ({})", peerID, nickname);
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error processing announce packet: {}", e.what());
    }
}

} // namespace bitchat
