#include "bitchat/services/network_service.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/protocol_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/protocol/packet_serializer.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
#include <chrono>
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
    bluetoothInterface->setPacketReceivedCallback([this](const BitchatPacket &packet) {
        onPacketReceived(packet);
    });
    // clang-format on

    // clang-format off
    bluetoothInterface->setPeerConnectedCallback([this](const std::string &uuid) {
        onPeerConnected(uuid);
    });
    // clang-format on

    // clang-format off
    bluetoothInterface->setPeerDisconnectedCallback([this](const std::string &uuid) {
        onPeerDisconnected(uuid);
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

void NetworkService::setLocalPeerID(const std::string &peerID)
{
    if (!bluetoothInterface)
    {
        spdlog::error("NetworkService: Cannot set peer ID without Bluetooth interface");
        return;
    }

    // Set the local peer ID in the Bluetooth interface
    bluetoothInterface->setLocalPeerID(peerID);
    localPeerID = peerID;

    // Set the peer ID in the announce runner
    if (announceRunner)
    {
        announceRunner->setLocalPeerID(peerID);
    }
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

std::map<std::string, BitchatPeer> NetworkService::getOnlinePeers() const
{
    std::lock_guard<std::mutex> lock(peersMutex);
    return onlinePeers;
}

size_t NetworkService::getConnectedPeersCount() const
{
    if (bluetoothInterface)
    {
        return bluetoothInterface->getConnectedPeersCount();
    }

    return 0;
}

bool NetworkService::isPeerOnline(const std::string &peerID) const
{
    std::lock_guard<std::mutex> lock(peersMutex);
    return onlinePeers.find(peerID) != onlinePeers.end();
}

std::optional<BitchatPeer> NetworkService::getPeerInfo(const std::string &peerID) const
{
    std::lock_guard<std::mutex> lock(peersMutex);

    auto it = onlinePeers.find(peerID);
    if (it != onlinePeers.end())
    {
        return it->second;
    }

    return std::nullopt;
}

void NetworkService::updatePeerInfo(const std::string &peerID, const BitchatPeer &peer)
{
    std::lock_guard<std::mutex> lock(peersMutex);
    onlinePeers[peerID] = peer;
}

void NetworkService::cleanupStalePeers(time_t timeout)
{
    std::lock_guard<std::mutex> lock(peersMutex);

    auto it = onlinePeers.begin();
    while (it != onlinePeers.end())
    {
        if (it->second.isStale(timeout))
        {
            spdlog::debug("Removing stale peer: {}", it->first);
            it = onlinePeers.erase(it);
        }
        else
        {
            ++it;
        }
    }
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

std::string NetworkService::getLocalPeerID() const
{
    return localPeerID;
}

bool NetworkService::isReady() const
{
    return bluetoothInterface && bluetoothInterface->isReady();
}

void NetworkService::setNickname(const std::string &nick)
{
    nickname = nick;

    // Set the nickname in the announce runner
    if (announceRunner)
    {
        announceRunner->setNickname(nick);
    }
}

void NetworkService::setAnnounceRunner(std::shared_ptr<BluetoothAnnounceRunner> runner)
{
    announceRunner = runner;
}

void NetworkService::setCleanupRunner(std::shared_ptr<CleanupRunner> runner)
{
    cleanupRunner = runner;
}

void NetworkService::onPeerConnected(const std::string &uuid)
{
    spdlog::info("Peer connected with UUID: {}", uuid);

    if (peerConnectedCallback)
    {
        peerConnectedCallback(uuid);
    }
}

void NetworkService::onPeerDisconnected(const std::string &uuid)
{
    std::lock_guard<std::mutex> lock(peersMutex);

    auto it = onlinePeers.find(uuid);

    if (it != onlinePeers.end())
    {
        std::string nickname = it->second.getNickname();
        onlinePeers.erase(it);

        spdlog::info("Peer disconnected with UUID: {} ({})", uuid, nickname);

        if (peerDisconnectedCallback)
        {
            peerDisconnectedCallback(uuid, nickname);
        }
    }
}

void NetworkService::onPacketReceived(const BitchatPacket &packet)
{
    processPacket(packet);
}

void NetworkService::processPacket(const BitchatPacket &packet)
{
    // Validate packet
    if (!packet.isValid())
    {
        spdlog::warn("Received invalid packet from {}", StringHelper::toHex(packet.getSenderID()));
        return;
    }

    // Check if we've already processed this message
    std::string messageID = StringHelper::toHex(packet.getSenderID()) + "_" + std::to_string(packet.getTimestamp());

    if (wasMessageProcessed(messageID))
    {
        return;
    }

    markMessageProcessed(messageID);

    // Process based on packet type
    switch (packet.getType())
    {
    case PKT_TYPE_ANNOUNCE:
        processAnnouncePacket(packet);
        break;
    case PKT_TYPE_MESSAGE:
        spdlog::debug("Received MESSAGE packet from {}", StringHelper::toHex(packet.getSenderID()));
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet);
        }
        break;
    case PKT_TYPE_LEAVE:
        spdlog::debug("Received LEAVE packet from {}", StringHelper::toHex(packet.getSenderID()));
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet);
        }
        break;
    case PKT_TYPE_NOISE_HANDSHAKE_INIT:
        spdlog::info("Received NOISE_HANDSHAKE_INIT from {} (payload size: {})", StringHelper::toHex(packet.getSenderID()), packet.getPayload().size());
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet);
        }
        break;
    case PKT_TYPE_NOISE_HANDSHAKE_RESP:
        spdlog::info("Received NOISE_HANDSHAKE_RESP from {}", StringHelper::toHex(packet.getSenderID()));
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet);
        }
        break;
    case PKT_TYPE_NOISE_ENCRYPTED:
        spdlog::info("Received NOISE_ENCRYPTED from {}", StringHelper::toHex(packet.getSenderID()));
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet);
        }
        break;
    case PKT_TYPE_NOISE_IDENTITY_ANNOUNCE:
        spdlog::info("Received NOISE_IDENTITY_ANNOUNCE from {}", StringHelper::toHex(packet.getSenderID()));
        if (packetReceivedCallback)
        {
            packetReceivedCallback(packet);
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

    std::lock_guard<std::mutex> lock(peersMutex);
    for (const auto &[peerID, peer] : onlinePeers)
    {
        if (peerID != senderID)
        {
            bluetoothInterface->sendPacketToPeer(relayPacket, peerID);
        }
    }
}

bool NetworkService::wasMessageProcessed(const std::string &messageID)
{
    std::lock_guard<std::mutex> lock(processedMutex);
    return processedMessages.find(messageID) != processedMessages.end();
}

void NetworkService::markMessageProcessed(const std::string &messageID)
{
    std::lock_guard<std::mutex> lock(processedMutex);
    processedMessages.insert(messageID);

    // Keep only last 1000 processed messages
    if (processedMessages.size() > 1000)
    {
        auto it = processedMessages.begin();
        std::advance(it, processedMessages.size() - 1000);
        processedMessages.erase(processedMessages.begin(), it);
    }
}

void NetworkService::processAnnouncePacket(const BitchatPacket &packet)
{
    try
    {
        PacketSerializer serializer;
        std::string nickname;
        serializer.parseAnnouncePayload(packet.getPayload(), nickname);

        std::string peerID = StringHelper::toHex(packet.getSenderID());

        {
            std::lock_guard<std::mutex> lock(peersMutex);

            // Check if peer is already in the list
            auto it = onlinePeers.find(peerID);
            if (it != onlinePeers.end())
            {
                // Update existing peer's last seen time
                it->second.updateLastSeen();
                spdlog::debug("Updated existing peer: {} ({})", peerID, nickname);

                // Don't notify about connection again
                return;
            }

            // Add new peer
            BitchatPeer peer(packet.getSenderID(), nickname);
            peer.updateLastSeen();
            onlinePeers[peerID] = peer;
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
