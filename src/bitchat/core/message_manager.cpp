#include "bitchat/core/message_manager.h"
#include "bitchat/compression/compression_manager.h"
#include "bitchat/core/network_manager.h"
#include "bitchat/crypto/crypto_manager.h"
#include "bitchat/helpers/protocol_helper.h"
#include "bitchat/noise/noise_session.h"
#include "bitchat/protocol/packet_serializer.h"
#include <algorithm>
#include <spdlog/spdlog.h>

namespace bitchat
{

MessageManager::MessageManager()
    : currentChannel("") // No default channel - user must join one explicitly
{
    nickname = ProtocolHelper::randomNickname();
}

bool MessageManager::initialize(std::shared_ptr<NetworkManager> network,
                                std::shared_ptr<CryptoManager> crypto,
                                std::shared_ptr<CompressionManager> compression,
                                std::shared_ptr<noise::NoiseSessionManager> noise)
{
    networkManager = network;
    cryptoManager = crypto;
    compressionManager = compression;
    noiseSessionManager = noise;

    if (!networkManager || !cryptoManager || !compressionManager)
    {
        spdlog::error("MessageManager: Invalid dependencies provided");
        return false;
    }

    // Set up network callbacks
    networkManager->setPacketReceivedCallback([this](const BitchatPacket &packet)
                                              { onPacketReceived(packet); });

    spdlog::info("MessageManager initialized");
    return true;
}

bool MessageManager::sendMessage(const std::string &content, const std::string &channel)
{
    if (!isReady())
    {
        spdlog::error("MessageManager: Not ready to send message");
        return false;
    }

    std::string targetChannel = channel.empty() ? currentChannel : channel;

    // Create message
    BitchatMessage message(nickname, content, targetChannel);
    message.setId(generateMessageId());

    // Create and send packet
    BitchatPacket packet = createMessagePacket(message);
    bool success = networkManager->sendPacket(packet);

    if (success)
    {
        // Add to our own history
        addMessageToHistory(message);
        spdlog::debug("Message sent: {}", content);
    }
    else
    {
        spdlog::error("Failed to send message");
    }

    return success;
}

bool MessageManager::sendPrivateMessage(const std::string &content, const std::string &recipientNickname)
{
    if (!isReady())
    {
        spdlog::error("MessageManager: Not ready to send private message");
        return false;
    }

    // Create private message
    BitchatMessage message(nickname, content, "");
    message.setId(generateMessageId());
    message.setPrivate(true);
    message.setRecipientNickname(recipientNickname);

    // Create and send packet
    BitchatPacket packet = createMessagePacket(message);
    bool success = networkManager->sendPacket(packet);

    if (success)
    {
        spdlog::debug("Private message sent to: {}", recipientNickname);
    }
    else
    {
        spdlog::error("Failed to send private message");
    }

    return success;
}

void MessageManager::joinChannel(const std::string &channel)
{
    if (channel.empty())
    {
        spdlog::error("MessageManager: Cannot join empty channel");
        return;
    }

    // Leave current channel if any
    if (!currentChannel.empty())
    {
        leaveChannel();
    }

    // Ensure channel starts with #
    std::string channelTag = channel;
    if (channelTag[0] != '#')
    {
        currentChannel = "#" + channel;
    }
    else
    {
        currentChannel = channel;
    }

    // Send channel announce packet
    BitchatPacket packet = createChannelAnnouncePacket(currentChannel, true);
    networkManager->sendPacket(packet);

    if (channelJoinedCallback)
    {
        channelJoinedCallback(currentChannel);
    }

    spdlog::info("Joined channel: {}", currentChannel);
}

void MessageManager::leaveChannel()
{
    if (currentChannel.empty())
    {
        return;
    }

    // Send channel leave packet
    BitchatPacket packet = createChannelAnnouncePacket(currentChannel, false);
    networkManager->sendPacket(packet);

    std::string oldChannel = currentChannel;
    currentChannel.clear();

    if (channelLeftCallback)
    {
        channelLeftCallback(oldChannel);
    }

    spdlog::info("Left channel: {}", oldChannel);
}

std::string MessageManager::getCurrentChannel() const
{
    return currentChannel;
}

std::vector<BitchatMessage> MessageManager::getMessageHistory() const
{
    if (currentChannel.empty())
    {
        return getMessageHistory("");
    }

    return getMessageHistory(currentChannel);
}

std::vector<BitchatMessage> MessageManager::getMessageHistory(const std::string &channel) const
{
    std::lock_guard<std::mutex> lock(historyMutex);
    auto it = messageHistory.find(channel);
    if (it != messageHistory.end())
    {
        return it->second;
    }
    return {};
}

void MessageManager::clearMessageHistory()
{
    std::lock_guard<std::mutex> lock(historyMutex);
    messageHistory.clear();
}

void MessageManager::setNickname(const std::string &nick)
{
    nickname = nick;

    // Update NetworkManager nickname for announce packets
    if (networkManager)
    {
        networkManager->setNickname(nick);
    }

    spdlog::info("Nickname changed to: {}", nickname);
}

std::string MessageManager::getNickname() const
{
    return nickname;
}

void MessageManager::setMessageReceivedCallback(MessageReceivedCallback callback)
{
    messageReceivedCallback = callback;
}

void MessageManager::setChannelJoinedCallback(ChannelJoinedCallback callback)
{
    channelJoinedCallback = callback;
}

void MessageManager::setChannelLeftCallback(ChannelLeftCallback callback)
{
    channelLeftCallback = callback;
}

void MessageManager::processPacket(const BitchatPacket &packet)
{
    onPacketReceived(packet);
}

bool MessageManager::isReady() const
{
    return networkManager && networkManager->isReady();
}

void MessageManager::onPacketReceived(const BitchatPacket &packet)
{
    switch (packet.getType())
    {
    case PKT_TYPE_MESSAGE:
        processMessagePacket(packet);
        break;
    case PKT_TYPE_CHANNEL_ANNOUNCE:
        processChannelAnnouncePacket(packet);
        break;
    default:
        spdlog::debug("Received packet type: {}", packet.getTypeString());
        break;
    }
}

void MessageManager::processMessagePacket(const BitchatPacket &packet)
{
    try
    {
        PacketSerializer serializer;
        BitchatMessage message = serializer.parseMessagePayload(packet.getPayload());

        spdlog::debug("Processing message packet - ID: {}, Sender: {}, Content: {}, Channel: {}, Private: {}",
                      message.getId(), message.getSender(), message.getContent(), message.getChannel(), message.isPrivate());

        // Check if we've already processed this message
        if (wasMessageProcessed(message.getId()))
        {
            spdlog::debug("Message already processed, skipping: {}", message.getId());
            return;
        }

        // IMPORTANT: Ignore messages from ourselves to prevent duplication
        std::string senderId = ProtocolHelper::toHexCompact(packet.getSenderId());
        std::string localPeerId = networkManager->getLocalPeerId();
        spdlog::debug("Message sender ID: {}, Local peer ID: {}", senderId, localPeerId);

        if (senderId == localPeerId)
        {
            spdlog::debug("Ignoring message from ourselves: {}", senderId);
            return;
        }

        markMessageProcessed(message.getId());

        // Add to history if it's for our current channel, default chat (empty channel), or a private message
        bool shouldAddToHistory = false;

        if (message.getChannel() == currentChannel)
        {
            spdlog::debug("Message is for current channel: {}", currentChannel);
            shouldAddToHistory = true;
        }
        else if (message.getChannel().empty() && currentChannel.empty())
        {
            // Default chat - both sender and receiver have empty channel
            spdlog::debug("Message is for default chat (empty channel)");
            shouldAddToHistory = true;
        }
        else if (message.isPrivate() && message.getRecipientNickname() == nickname)
        {
            spdlog::debug("Message is private for us: {}", nickname);
            shouldAddToHistory = true;
        }
        else
        {
            spdlog::debug("Message not for us - Channel: {} (current: {}), Private: {}, Recipient: {} (our nick: {})",
                          message.getChannel(), currentChannel, message.isPrivate(), message.getRecipientNickname(), nickname);
        }

        if (shouldAddToHistory)
        {
            addMessageToHistory(message);
            spdlog::debug("Added message to history");
        }

        // Notify callback
        if (messageReceivedCallback)
        {
            spdlog::debug("Calling message received callback");
            messageReceivedCallback(message);
        }
        else
        {
            spdlog::warn("No message received callback set!");
        }

        spdlog::debug("Processed message from: {}", message.getSender());
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error processing message packet: {}", e.what());
    }
}

void MessageManager::processChannelAnnouncePacket(const BitchatPacket &packet)
{
    try
    {
        PacketSerializer serializer;
        std::string channel;
        bool joining;
        serializer.parseChannelAnnouncePayload(packet.getPayload(), channel, joining);

        std::string peerId = ProtocolHelper::toHexCompact(packet.getSenderId());
        auto peerInfo = networkManager->getPeerInfo(peerId);

        if (peerInfo)
        {
            peerInfo->setChannel(joining ? channel : "");
            networkManager->updatePeerInfo(peerId, *peerInfo);
        }

        spdlog::debug("Processed channel announce: {} {} channel {}",
                      peerId, joining ? "joined" : "left", channel);
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error processing channel announce packet: {}", e.what());
    }
}

void MessageManager::addMessageToHistory(const BitchatMessage &message)
{
    std::lock_guard<std::mutex> lock(historyMutex);

    std::string channel = message.getChannel();

    if (channel.empty() && message.isPrivate())
    {
        channel = "private";
    }

    messageHistory[channel].push_back(message);

    // Keep history size limited
    if (messageHistory[channel].size() > MAX_HISTORY_SIZE)
    {
        messageHistory[channel].erase(messageHistory[channel].begin());
    }
}

bool MessageManager::wasMessageProcessed(const std::string &messageId)
{
    std::lock_guard<std::mutex> lock(processedMutex);
    return processedMessages.find(messageId) != processedMessages.end();
}

void MessageManager::markMessageProcessed(const std::string &messageId)
{
    std::lock_guard<std::mutex> lock(processedMutex);
    processedMessages.insert(messageId);

    // Keep processed messages size limited
    if (processedMessages.size() > MAX_PROCESSED_MESSAGES)
    {
        auto it = processedMessages.begin();
        std::advance(it, processedMessages.size() - MAX_PROCESSED_MESSAGES);
        processedMessages.erase(processedMessages.begin(), it);
    }
}

BitchatPacket MessageManager::createMessagePacket(const BitchatMessage &message)
{
    PacketSerializer serializer;
    std::vector<uint8_t> payload = serializer.makeMessagePayload(message);

    // Compress payload if beneficial
    if (compressionManager && compressionManager->shouldCompress(payload))
    {
        payload = compressionManager->compressData(payload);
    }

    // Check if we should encrypt this message with Noise
    uint8_t packetType = PKT_TYPE_MESSAGE;

    if (noiseSessionManager && !message.isPrivate())
    {
        // For channel messages, check if we have any established sessions
        auto establishedSessionIDs = noiseSessionManager->getEstablishedSessionIDs();
        if (!establishedSessionIDs.empty())
        {
            // Use the first established session for encryption
            auto firstPeerId = establishedSessionIDs[0];
            try
            {
                auto encryptedPayload = noiseSessionManager->encrypt(payload, firstPeerId);

                // Use encrypted packet type
                packetType = PKT_TYPE_NOISE_ENCRYPTED;
                payload = encryptedPayload;

                spdlog::debug("Message encrypted with Noise protocol for peer: {}", firstPeerId);
            }
            catch (const std::exception &e)
            {
                spdlog::warn("Failed to encrypt message with Noise: {}, sending as plaintext", e.what());
                // Fall back to plaintext
                packetType = PKT_TYPE_MESSAGE;
            }
        }
        else
        {
            spdlog::debug("No established Noise sessions available, sending as plaintext");
        }
    }

    BitchatPacket packet(packetType, payload);
    packet.setSenderId(ProtocolHelper::stringToVector(networkManager->getLocalPeerId()));
    packet.setTimestamp(ProtocolHelper::getCurrentTimestamp());
    packet.setCompressed(compressionManager && compressionManager->shouldCompress(payload));

    // Set recipient ID for channel messages (broadcast)
    if (!message.isPrivate())
    {
        // Broadcast to all
        packet.setRecipientID(std::vector<uint8_t>(8, 0xFF));
        packet.setHasRecipient(true);
    }

    // Sign packet if crypto manager is available
    if (cryptoManager)
    {
        std::vector<uint8_t> signature = cryptoManager->signData(payload);
        packet.setSignature(signature);
        packet.setHasSignature(true);
    }

    return packet;
}

BitchatPacket MessageManager::createAnnouncePacket()
{
    PacketSerializer serializer;
    std::vector<uint8_t> payload = serializer.makeAnnouncePayload(nickname);

    BitchatPacket packet(PKT_TYPE_ANNOUNCE, payload);
    packet.setSenderId(ProtocolHelper::stringToVector(networkManager->getLocalPeerId()));
    packet.setTimestamp(ProtocolHelper::getCurrentTimestamp());

    return packet;
}

BitchatPacket MessageManager::createChannelAnnouncePacket(const std::string &channel, bool joining)
{
    PacketSerializer serializer;
    std::vector<uint8_t> payload = serializer.makeChannelAnnouncePayload(channel, joining);

    BitchatPacket packet(PKT_TYPE_CHANNEL_ANNOUNCE, payload);
    packet.setSenderId(ProtocolHelper::stringToVector(networkManager->getLocalPeerId()));
    packet.setTimestamp(ProtocolHelper::getCurrentTimestamp());

    return packet;
}

std::string MessageManager::generateMessageId() const
{
    return ProtocolHelper::uuidv4();
}

} // namespace bitchat
