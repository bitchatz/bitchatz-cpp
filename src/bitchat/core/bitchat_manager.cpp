#include "bitchat/core/bitchat_manager.h"
#include "bitchat/platform/bluetooth_factory.h"
#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>

namespace bitchat
{

BitchatManager::BitchatManager()
    : shouldExit(false)
{
}

BitchatManager::~BitchatManager()
{
    stop();
}

bool BitchatManager::initialize()
{
    // Generate peer ID and random nickname
    peerId = randomPeerId();
    nickname = randomNickname();
    currentChannel = "";

    // Initialize managers
    cryptoManager = std::make_unique<CryptoManager>();
    compressionManager = std::make_unique<CompressionManager>();
    packetSerializer = std::make_unique<PacketSerializer>();

    // Initialize crypto
    if (!cryptoManager->initialize())
    {
        std::cerr << "Failed to initialize crypto manager" << std::endl;
        return false;
    }

    if (!cryptoManager->generateOrLoadKeyPair())
    {
        std::cerr << "Failed to generate or load key pair" << std::endl;
        return false;
    }

    // Create Bluetooth interface
    try
    {
        bluetooth = createBluetoothInterface();
        if (!bluetooth)
        {
            throw std::runtime_error("Failed to create Bluetooth interface for current platform");
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Failed to create Bluetooth interface: " << e.what() << std::endl;
        return false;
    }

    // Set Bluetooth callbacks
    bluetooth->setPeerDisconnectedCallback([this](const std::string &peerId)
                                           { onPeerDisconnected(peerId); });

    bluetooth->setPacketReceivedCallback([this](const BitchatPacket &packet)
                                         { onPacketReceived(packet); });

    return true;
}

bool BitchatManager::start()
{
    if (!bluetooth)
    {
        std::cerr << "Bluetooth interface not initialized" << std::endl;
        return false;
    }

    // Initialize Bluetooth
    if (!bluetooth->initialize())
    {
        std::cerr << "Failed to initialize Bluetooth" << std::endl;
        return false;
    }

    // Start Bluetooth
    if (!bluetooth->start())
    {
        std::cerr << "Failed to start Bluetooth" << std::endl;
        return false;
    }

    // Start background threads
    shouldExit = false;
    announceThread = std::thread(&BitchatManager::announceLoop, this);
    cleanupThread = std::thread(&BitchatManager::cleanupLoop, this);

    return true;
}

void BitchatManager::stop()
{
    shouldExit = true;

    // Wait for threads to finish
    if (announceThread.joinable())
    {
        announceThread.join();
    }
    if (cleanupThread.joinable())
    {
        cleanupThread.join();
    }

    // Stop Bluetooth
    if (bluetooth)
    {
        bluetooth->stop();
    }
}

bool BitchatManager::sendMessage(const std::string &content)
{
    if (content.empty())
    {
        return false;
    }

    BitchatMessage message;
    message.id = uuidv4();
    message.sender = nickname;
    message.content = content;
    message.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();

    // Only set channel if we're actually in a channel (not in general/main chat)
    if (currentChannel != "#general")
    {
        message.channel = currentChannel;
        if (!message.channel.empty() && message.channel[0] != '#')
        {
            message.channel = "#" + message.channel;
        }
    }

    // Use peer ID string for Swift compatibility - convert to vector
    message.senderPeerID = stringToVector(peerId);

    auto payload = packetSerializer->makeMessagePayload(message);
    auto packet = packetSerializer->makePacket(PKT_TYPE_MESSAGE, payload, true, true, peerId);

    // Add signature
    auto signature = cryptoManager->signData(payload);
    if (signature.empty())
    {
        std::cerr << "Failed to sign message" << std::endl;
        return false;
    }
    packet.signature = signature;

    // Send packet
    if (!bluetooth->sendPacket(packet))
    {
        std::cerr << "Failed to send message packet" << std::endl;
        return false;
    }

    // Store in history
    {
        std::lock_guard<std::mutex> lock(messagesMutex);
        messageHistory.push_back(message);
        if (messageHistory.size() > 100)
        {
            messageHistory.erase(messageHistory.begin());
        }
    }

    return true;
}

void BitchatManager::joinChannel(const std::string &channel)
{
    currentChannel = channel;
    if (!currentChannel.empty() && currentChannel[0] != '#')
    {
        currentChannel = "#" + currentChannel;
    }
}

void BitchatManager::setNickname(const std::string &nickname)
{
    this->nickname = nickname;
}

std::string BitchatManager::getCurrentChannel() const
{
    return currentChannel;
}

std::string BitchatManager::getNickname() const
{
    return nickname;
}

std::string BitchatManager::getPeerId() const
{
    return peerId;
}

std::map<std::string, OnlinePeer> BitchatManager::getOnlinePeers() const
{
    std::lock_guard<std::mutex> lock(peersMutex);
    return onlinePeers;
}

std::vector<BitchatMessage> BitchatManager::getMessageHistory() const
{
    std::lock_guard<std::mutex> lock(messagesMutex);
    return messageHistory;
}

bool BitchatManager::isReady() const
{
    return bluetooth && bluetooth->isReady();
}

void BitchatManager::setMessageCallback(MessageCallback callback)
{
    messageCallback = callback;
}

void BitchatManager::setPeerJoinedCallback(PeerCallback callback)
{
    peerJoinedCallback = callback;
}

void BitchatManager::setPeerLeftCallback(PeerCallback callback)
{
    peerLeftCallback = callback;
}

void BitchatManager::setStatusCallback(StatusCallback callback)
{
    statusCallback = callback;
}

// Bluetooth event handlers
void BitchatManager::onPeerConnected(const std::string &peerId, const std::string &nickname)
{
    std::lock_guard<std::mutex> lock(peersMutex);

    OnlinePeer &peer = onlinePeers[peerId];
    bool isNewPeer = !peer.hasAnnounced;
    peer.nick = nickname;
    peer.canal = "";
    peer.peerid = stringToVector(peerId);
    peer.lastSeen = time(nullptr);
    peer.hasAnnounced = true;

    if (isNewPeer && peerId != this->peerId && peerJoinedCallback)
    {
        peerJoinedCallback(peerId, nickname);
    }
}

void BitchatManager::onPeerDisconnected(const std::string &peerId)
{
    std::string nickname;

    {
        std::lock_guard<std::mutex> lock(peersMutex);
        auto it = onlinePeers.find(peerId);
        if (it != onlinePeers.end())
        {
            nickname = it->second.nick;
            onlinePeers.erase(it);
        }
    }

    if (!nickname.empty() && peerLeftCallback)
    {
        peerLeftCallback(peerId, nickname);
    }
}

void BitchatManager::onMessageReceived(const BitchatMessage &message)
{
    // Check if message is for current channel or is broadcast
    std::string messageChannel = message.channel;
    std::string currentChannelNormalized = currentChannel;

    if (!messageChannel.empty() && messageChannel[0] == '#')
    {
        messageChannel = messageChannel.substr(1);
    }
    if (!currentChannelNormalized.empty() && currentChannelNormalized[0] == '#')
    {
        currentChannelNormalized = currentChannelNormalized.substr(1);
    }

    bool isBroadcast = true; // For now, treat all messages as broadcast
    if (isBroadcast || messageChannel == currentChannelNormalized || message.channel.empty())
    {
        // Skip empty messages
        if (message.content.empty())
        {
            return;
        }

        // Store in history
        {
            std::lock_guard<std::mutex> lock(messagesMutex);
            messageHistory.push_back(message);
            if (messageHistory.size() > 100)
            {
                messageHistory.erase(messageHistory.begin());
            }
        }

        // Update peer info
        std::string senderId;
        if (!message.senderPeerID.empty())
        {
            senderId = normalizePeerId(toHexCompact(message.senderPeerID));
        }
        else
        {
            senderId = "unknown";
        }

        {
            std::lock_guard<std::mutex> lock(peersMutex);
            OnlinePeer &peer = onlinePeers[senderId];
            peer.nick = message.sender;
            peer.canal = message.channel;
            peer.peerid = message.senderPeerID.empty() ? stringToVector(senderId) : message.senderPeerID;
            peer.lastSeen = time(nullptr);
        }

        // Call message callback
        if (messageCallback)
        {
            messageCallback(message);
        }
    }
}

void BitchatManager::onPacketReceived(const BitchatPacket &packet)
{
    std::string messageId = std::to_string(packet.timestamp) + "-" + vectorToString(packet.senderID);

    if (wasMessageProcessed(messageId))
    {
        return; // Already processed
    }

    markMessageProcessed(messageId);
    processPacket(packet);
}

// Internal methods
void BitchatManager::announceLoop()
{
    while (!shouldExit)
    {
        auto payload = packetSerializer->makeAnnouncePayload(nickname);
        auto packet = packetSerializer->makePacket(PKT_TYPE_ANNOUNCE, payload, true, true, peerId);

        // Add signature
        auto signature = cryptoManager->signData(payload);
        if (!signature.empty())
        {
            packet.signature = signature;
        }

        bluetooth->sendPacket(packet);

        // Sleep for announce interval
        for (int i = 0; i < ANNOUNCE_INTERVAL && !shouldExit; ++i)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void BitchatManager::cleanupLoop()
{
    while (!shouldExit)
    {
        cleanupStalePeers();

        // Sleep for cleanup interval
        for (int i = 0; i < CLEANUP_INTERVAL && !shouldExit; ++i)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void BitchatManager::cleanupStalePeers()
{
    std::lock_guard<std::mutex> lock(peersMutex);
    time_t now = time(nullptr);

    for (auto it = onlinePeers.begin(); it != onlinePeers.end();)
    {
        if (now - it->second.lastSeen > PEER_TIMEOUT)
        {
            it = onlinePeers.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void BitchatManager::processPacket(const BitchatPacket &packet)
{
    switch (packet.type)
    {
    case PKT_TYPE_MESSAGE:
    {
        // Verify if it's our own message
        std::string senderId = normalizePeerId(vectorToString(packet.senderID));
        if (senderId == peerId)
        {
            return; // Ignore our own messages
        }

        // Verify signature if present
        if (packet.flags & FLAG_HAS_SIGNATURE && !packet.signature.empty())
        {
            if (!cryptoManager->verifySignature(packet.payload, packet.signature, senderId))
            {
                // Signature verification failed, but continue processing
                // Key might not be available yet
            }
        }

        // Parse message
        BitchatMessage message = packetSerializer->parseMessagePayload(packet.payload);
        onMessageReceived(message);
        break;
    }

    case PKT_TYPE_ANNOUNCE:
    {
        std::string nickname;
        packetSerializer->parseAnnouncePayload(packet.payload, nickname);
        std::string peerId = normalizePeerId(vectorToString(packet.senderID));
        onPeerConnected(peerId, nickname);
        break;
    }

    case PKT_TYPE_KEYEXCHANGE:
    {
        std::string peerId = normalizePeerId(vectorToString(packet.senderID));
        cryptoManager->addPeerPublicKey(peerId, packet.payload);
        break;
    }

    case PKT_TYPE_LEAVE:
    {
        std::string senderId = normalizePeerId(vectorToString(packet.senderID));
        onPeerDisconnected(senderId);
        break;
    }
    }

    // Relay if TTL > 0
    if (packet.ttl > 1)
    {
        relayPacket(packet);
    }
}

void BitchatManager::relayPacket(const BitchatPacket &packet)
{
    BitchatPacket relayPacket = packet;
    relayPacket.ttl--;
    bluetooth->sendPacket(relayPacket);
}

bool BitchatManager::wasMessageProcessed(const std::string &messageId)
{
    std::lock_guard<std::mutex> lock(processedMutex);
    return processedMessages.find(messageId) != processedMessages.end();
}

void BitchatManager::markMessageProcessed(const std::string &messageId)
{
    std::lock_guard<std::mutex> lock(processedMutex);
    processedMessages.insert(messageId);
}

} // namespace bitchat
