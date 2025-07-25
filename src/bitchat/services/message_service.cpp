#include "bitchat/services/message_service.h"
#include "bitchat/helpers/compression_helper.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/protocol_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/noise/noise_session.h"
#include "bitchat/protocol/packet_serializer.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/network_service.h"
#include <algorithm>
#include <spdlog/spdlog.h>

namespace bitchat
{

MessageService::MessageService()
{
    // Pass
}

bool MessageService::initialize(std::shared_ptr<NetworkService> network, std::shared_ptr<CryptoService> crypto, std::shared_ptr<noise::NoiseSessionManager> noise)
{
    networkService = network;
    cryptoService = crypto;
    noiseSessionManager = noise;

    if (!networkService || !cryptoService)
    {
        spdlog::error("MessageService: Invalid dependencies provided");
        return false;
    }

    // Set up network callbacks
    // clang-format off
    networkService->setPacketReceivedCallback([this](const BitchatPacket &packet, const std::string &peripheralID) {
        onPacketReceived(packet, peripheralID);
    });
    // clang-format on

    spdlog::info("MessageService initialized");

    return true;
}

bool MessageService::sendMessage(const std::string &content, const std::string &channel)
{
    if (!isReady())
    {
        spdlog::error("MessageService: Not ready to send message");
        return false;
    }

    std::string targetChannel = channel.empty() ? BitchatData::shared()->getCurrentChannel() : channel;
    std::string senderNickname = BitchatData::shared()->getNickname();

    // Create message
    BitchatMessage message(senderNickname, content, targetChannel);
    message.setId(generateMessageID());

    // Create and send packet
    BitchatPacket packet = createMessagePacket(message);
    bool success = networkService->sendPacket(packet);

    if (success)
    {
        // Add to our own history
        std::string channel = message.getChannel();

        if (channel.empty() && message.isPrivate())
        {
            channel = "private";
        }

        BitchatData::shared()->addMessageToHistory(message, channel);

        spdlog::debug("Message sent: {}", content);
    }
    else
    {
        spdlog::error("Failed to send message");
    }

    return success;
}

bool MessageService::sendPrivateMessage(const std::string &content, const std::string &recipientNickname)
{
    if (!isReady())
    {
        spdlog::error("MessageService: Not ready to send private message");
        return false;
    }

    std::string senderNickname = BitchatData::shared()->getNickname();

    // Create private message
    BitchatMessage message(senderNickname, content, "");
    message.setId(generateMessageID());
    message.setPrivate(true);
    message.setRecipientNickname(recipientNickname);

    // Create and send packet
    BitchatPacket packet = createMessagePacket(message);
    bool success = networkService->sendPacket(packet);

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

void MessageService::joinChannel(const std::string &channel)
{
    if (channel.empty())
    {
        spdlog::error("MessageService: Cannot join empty channel");
        return;
    }

    // Leave current channel if any
    std::string currentChannel = BitchatData::shared()->getCurrentChannel();

    if (!currentChannel.empty())
    {
        leaveChannel();
    }

    // Ensure channel starts with #
    std::string newChannel;
    if (channel[0] != '#')
    {
        newChannel = "#" + channel;
    }
    else
    {
        newChannel = channel;
    }

    // Set the new channel in data
    BitchatData::shared()->setCurrentChannel(newChannel);

    // Send channel announce packet
    BitchatPacket packet = createChannelAnnouncePacket(newChannel, true);
    networkService->sendPacket(packet);

    if (channelJoinedCallback)
    {
        channelJoinedCallback(newChannel);
    }

    spdlog::info("Joined channel: {}", newChannel);
}

void MessageService::leaveChannel()
{
    std::string currentChannel = BitchatData::shared()->getCurrentChannel();

    if (currentChannel.empty())
    {
        return;
    }

    // Send channel leave packet
    BitchatPacket packet = createChannelAnnouncePacket(currentChannel, false);
    networkService->sendPacket(packet);

    std::string oldChannel = currentChannel;
    BitchatData::shared()->setCurrentChannel("");

    if (channelLeftCallback)
    {
        channelLeftCallback(oldChannel);
    }

    spdlog::info("Left channel: {}", oldChannel);
}

void MessageService::setMessageReceivedCallback(MessageReceivedCallback callback)
{
    messageReceivedCallback = callback;
}

void MessageService::setChannelJoinedCallback(ChannelJoinedCallback callback)
{
    channelJoinedCallback = callback;
}

void MessageService::setChannelLeftCallback(ChannelLeftCallback callback)
{
    channelLeftCallback = callback;
}

void MessageService::processPacket(const BitchatPacket &packet, const std::string &peripheralID)
{
    onPacketReceived(packet, peripheralID);
}

bool MessageService::isReady() const
{
    return networkService && networkService->isReady();
}

void MessageService::onPacketReceived(const BitchatPacket &packet, [[maybe_unused]] const std::string &peripheralID)
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

void MessageService::processMessagePacket(const BitchatPacket &packet)
{
    try
    {
        PacketSerializer serializer;
        BitchatMessage message = serializer.parseMessagePayload(packet.getPayload());

        spdlog::debug("Processing message packet - ID: {}, Sender: {}, Content: {}, Channel: {}, Private: {}", message.getId(), message.getSender(), message.getContent(), message.getChannel(), message.isPrivate());

        // Check if we've already processed this message
        if (BitchatData::shared()->wasMessageProcessed(message.getId()))
        {
            spdlog::debug("Message already processed, skipping: {}", message.getId());
            return;
        }

        // Ignore messages from ourselves to prevent duplication
        std::string senderID = StringHelper::toHex(packet.getSenderID());
        std::string localPeerID = BitchatData::shared()->getPeerID();
        spdlog::debug("Message sender ID: {}, Local peer ID: {}", senderID, localPeerID);

        if (senderID == localPeerID)
        {
            spdlog::debug("Ignoring message from ourselves: {}", senderID);
            return;
        }

        BitchatData::shared()->markMessageProcessed(message.getId());

        // Add to history if it's for our current channel, default chat (empty channel), or a private message
        bool shouldAddToHistory = false;

        std::string currentChannel = BitchatData::shared()->getCurrentChannel();

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
        else if (message.isPrivate() && message.getRecipientNickname() == BitchatData::shared()->getNickname())
        {
            std::string nickname = BitchatData::shared()->getNickname();
            spdlog::debug("Message is private for us: {}", nickname);
            shouldAddToHistory = true;
        }
        else
        {
            std::string nickname = BitchatData::shared()->getNickname();
            std::string currentChannel = BitchatData::shared()->getCurrentChannel();
            spdlog::debug("Message not for us - Channel: {} (current: {}), Private: {}, Recipient: {} (our nick: {})", message.getChannel(), currentChannel, message.isPrivate(), message.getRecipientNickname(), nickname);
        }

        if (shouldAddToHistory)
        {
            std::string channel = message.getChannel();

            if (channel.empty() && message.isPrivate())
            {
                channel = "private";
            }

            BitchatData::shared()->addMessageToHistory(message, channel);

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

void MessageService::processChannelAnnouncePacket(const BitchatPacket &packet)
{
    try
    {
        PacketSerializer serializer;
        std::string channel;
        bool joining;
        serializer.parseChannelAnnouncePayload(packet.getPayload(), channel, joining);

        std::string peerID = StringHelper::toHex(packet.getSenderID());
        auto peerInfo = BitchatData::shared()->getPeerInfo(peerID);

        if (peerInfo)
        {
            BitchatPeer updatedPeer = *peerInfo;
            updatedPeer.setChannel(joining ? channel : "");
            BitchatData::shared()->updatePeer(updatedPeer);
        }

        spdlog::debug("Processed channel announce: {} {} channel {}", peerID, joining ? "joined" : "left", channel);
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error processing channel announce packet: {}", e.what());
    }
}

BitchatPacket MessageService::createMessagePacket(const BitchatMessage &message)
{
    PacketSerializer serializer;
    std::vector<uint8_t> payload = serializer.makeMessagePayload(message);

    // Compress payload if beneficial
    if (CompressionHelper::shouldCompress(payload))
    {
        payload = CompressionHelper::compressData(payload);
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
    packet.setSenderID(StringHelper::stringToVector(BitchatData::shared()->getPeerID()));
    packet.setTimestamp(DateTimeHelper::getCurrentTimestamp());
    packet.setCompressed(CompressionHelper::shouldCompress(payload));

    // Set recipient ID for channel messages (broadcast)
    if (!message.isPrivate())
    {
        // Broadcast to all
        packet.setRecipientID(std::vector<uint8_t>(8, 0xFF));
        packet.setHasRecipient(true);
    }

    // Sign packet if crypto manager is available
    if (cryptoService)
    {
        std::vector<uint8_t> signature = cryptoService->signData(payload);
        packet.setSignature(signature);
        packet.setHasSignature(true);
    }

    return packet;
}

BitchatPacket MessageService::createAnnouncePacket()
{
    PacketSerializer serializer;
    std::string nickname = BitchatData::shared()->getNickname();
    std::vector<uint8_t> payload = serializer.makeAnnouncePayload(nickname);

    BitchatPacket packet(PKT_TYPE_ANNOUNCE, payload);
    packet.setSenderID(StringHelper::stringToVector(BitchatData::shared()->getPeerID()));
    packet.setTimestamp(DateTimeHelper::getCurrentTimestamp());

    return packet;
}

BitchatPacket MessageService::createChannelAnnouncePacket(const std::string &channel, bool joining)
{
    PacketSerializer serializer;
    std::vector<uint8_t> payload = serializer.makeChannelAnnouncePayload(channel, joining);

    BitchatPacket packet(PKT_TYPE_CHANNEL_ANNOUNCE, payload);
    packet.setTimestamp(DateTimeHelper::getCurrentTimestamp());

    return packet;
}

std::string MessageService::generateMessageID() const
{
    return StringHelper::createUUID();
}

} // namespace bitchat
