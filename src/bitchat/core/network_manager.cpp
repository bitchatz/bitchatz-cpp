#include "bitchat/core/network_manager.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/protocol_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/platform/bluetooth_interface.h"
#include "bitchat/protocol/packet_serializer.h"
#include <chrono>
#include <spdlog/spdlog.h>

namespace bitchat
{

NetworkManager::NetworkManager()
    : shouldExit(false)
{
}

NetworkManager::~NetworkManager()
{
    stop();
}

bool NetworkManager::initialize(std::shared_ptr<BluetoothInterface> bluetooth)
{
    bluetoothInterface = bluetooth;

    if (!bluetoothInterface)
    {
        spdlog::error("NetworkManager: Bluetooth interface is null");
        return false;
    }

    // Set up Bluetooth callbacks
    // clang-format off
    bluetoothInterface->setPacketReceivedCallback([this](const BitchatPacket &packet) {
        onPacketReceived(packet);
    });
    // clang-format on

    // clang-format off
    bluetoothInterface->setPeerDisconnectedCallback([this](const std::string &peerID) {
        onPeerDisconnected(peerID);
    });
    // clang-format on

    spdlog::info("NetworkManager initialized");
    return true;
}

void NetworkManager::setLocalPeerID(const std::string &peerID)
{
    if (!bluetoothInterface)
    {
        spdlog::error("NetworkManager: Cannot set peer ID without Bluetooth interface");
        return;
    }

    // Set the local peer ID in the Bluetooth interface
    bluetoothInterface->setLocalPeerID(peerID);
    localPeerID = peerID;
}

bool NetworkManager::start()
{
    if (!bluetoothInterface)
    {
        spdlog::error("NetworkManager: Cannot start without Bluetooth interface");
        return false;
    }

    if (!bluetoothInterface->initialize())
    {
        spdlog::error("NetworkManager: Failed to initialize Bluetooth interface");
        return false;
    }

    if (!bluetoothInterface->start())
    {
        spdlog::error("NetworkManager: Failed to start Bluetooth interface");
        return false;
    }

    shouldExit = false;

    // Start background threads
    announceThread = std::thread(&NetworkManager::announceLoop, this);
    cleanupThread = std::thread(&NetworkManager::cleanupLoop, this);

    spdlog::info("NetworkManager started");

    return true;
}

void NetworkManager::stop()
{
    shouldExit = true;

    if (announceThread.joinable())
    {
        announceThread.join();
    }

    if (cleanupThread.joinable())
    {
        cleanupThread.join();
    }

    if (bluetoothInterface)
    {
        bluetoothInterface->stop();
    }

    spdlog::info("NetworkManager stopped");
}

bool NetworkManager::sendPacket(const BitchatPacket &packet)
{
    if (!bluetoothInterface || !isReady())
    {
        return false;
    }

    return bluetoothInterface->sendPacket(packet);
}

bool NetworkManager::sendPacketToPeer(const BitchatPacket &packet, const std::string &peerID)
{
    if (!bluetoothInterface || !isReady())
    {
        return false;
    }

    return bluetoothInterface->sendPacketToPeer(packet, peerID);
}

std::map<std::string, BitchatPeer> NetworkManager::getOnlinePeers() const
{
    std::lock_guard<std::mutex> lock(peersMutex);
    return onlinePeers;
}

size_t NetworkManager::getConnectedPeersCount() const
{
    if (!bluetoothInterface)
    {
        return 0;
    }
    return bluetoothInterface->getConnectedPeersCount();
}

bool NetworkManager::isPeerOnline(const std::string &peerID) const
{
    std::lock_guard<std::mutex> lock(peersMutex);
    return onlinePeers.find(peerID) != onlinePeers.end();
}

std::optional<BitchatPeer> NetworkManager::getPeerInfo(const std::string &peerID) const
{
    std::lock_guard<std::mutex> lock(peersMutex);

    auto it = onlinePeers.find(peerID);
    if (it != onlinePeers.end())
    {
        return it->second;
    }

    return std::nullopt;
}

void NetworkManager::updatePeerInfo(const std::string &peerID, const BitchatPeer &peer)
{
    std::lock_guard<std::mutex> lock(peersMutex);
    onlinePeers[peerID] = peer;
}

void NetworkManager::cleanupStalePeers(time_t timeout)
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

void NetworkManager::setPacketReceivedCallback(PacketReceivedCallback callback)
{
    packetReceivedCallback = callback;
}

void NetworkManager::setPeerConnectedCallback(PeerConnectedCallback callback)
{
    peerConnectedCallback = callback;
}

void NetworkManager::setPeerDisconnectedCallback(PeerDisconnectedCallback callback)
{
    peerDisconnectedCallback = callback;
}

std::string NetworkManager::getLocalPeerID() const
{
    return localPeerID;
}

bool NetworkManager::isReady() const
{
    return bluetoothInterface && bluetoothInterface->isReady();
}

void NetworkManager::setNickname(const std::string &nick)
{
    nickname = nick;
}

void NetworkManager::announceLoop()
{
    spdlog::info("NetworkManager: Announce loop started");
    PacketSerializer serializer;

    while (!shouldExit)
    {
        try
        {
            // Create announce packet with nickname
            std::vector<uint8_t> payload = serializer.makeAnnouncePayload(nickname);

            BitchatPacket announcePacket(PKT_TYPE_ANNOUNCE, payload);

            // Convert hex string to bytes correctly
            std::vector<uint8_t> senderID;

            for (size_t i = 0; i < localPeerID.length(); i += 2)
            {
                std::string byteString = localPeerID.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
                senderID.push_back(byte);
            }

            announcePacket.setSenderID(senderID);
            announcePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());

            // Send announce packet
            if (bluetoothInterface && bluetoothInterface->isReady())
            {
                bluetoothInterface->sendPacket(announcePacket);
            }

            // Sleep for announce interval
            std::this_thread::sleep_for(std::chrono::seconds(ANNOUNCE_INTERVAL));
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error in announce loop: {}", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void NetworkManager::cleanupLoop()
{
    while (!shouldExit)
    {
        try
        {
            cleanupStalePeers(PEER_TIMEOUT);
            std::this_thread::sleep_for(std::chrono::seconds(CLEANUP_INTERVAL));
        }
        catch (const std::exception &e)
        {
            spdlog::error("Error in cleanup loop: {}", e.what());
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void NetworkManager::onPeerConnected(const std::string &peerID, const std::string &nickname)
{
    spdlog::info("Peer connected: {} ({})", peerID, nickname);

    if (peerConnectedCallback)
    {
        peerConnectedCallback(peerID, nickname);
    }
}

void NetworkManager::onPeerDisconnected(const std::string &peerID)
{
    std::string nickname;

    {
        std::lock_guard<std::mutex> lock(peersMutex);
        auto it = onlinePeers.find(peerID);
        if (it != onlinePeers.end())
        {
            nickname = it->second.getNickname();
            onlinePeers.erase(it);
        }
    }

    spdlog::info("Peer disconnected: {} ({})", peerID, nickname);

    if (peerDisconnectedCallback)
    {
        peerDisconnectedCallback(peerID, nickname);
    }
}

void NetworkManager::onPacketReceived(const BitchatPacket &packet)
{
    processPacket(packet);
}

void NetworkManager::processPacket(const BitchatPacket &packet)
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

void NetworkManager::relayPacket(const BitchatPacket &packet)
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

bool NetworkManager::wasMessageProcessed(const std::string &messageID)
{
    std::lock_guard<std::mutex> lock(processedMutex);
    return processedMessages.find(messageID) != processedMessages.end();
}

void NetworkManager::markMessageProcessed(const std::string &messageID)
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

void NetworkManager::processAnnouncePacket(const BitchatPacket &packet)
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
        onPeerConnected(peerID, nickname);

        spdlog::debug("Processed announce from: {} ({})", peerID, nickname);
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error processing announce packet: {}", e.what());
    }
}

} // namespace bitchat
