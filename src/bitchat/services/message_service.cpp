#include "bitchat/services/message_service.h"
#include "bitchat/core/bitchat_data.h"
#include "bitchat/core/constants.h"
#include "bitchat/helpers/compression_helper.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/protocol_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/protocol/packet_serializer.h"
#include "bitchat/services/crypto_service.h"
#include "bitchat/services/network_service.h"
#include "bitchat/services/noise_service.h"
#include <algorithm>
#include <spdlog/spdlog.h>

namespace bitchat
{

MessageService::MessageService()
{
    // Pass
}

bool MessageService::initialize(std::shared_ptr<NetworkService> networkService, std::shared_ptr<CryptoService> cryptoService, std::shared_ptr<NoiseService> noiseService)
{
    // Set services
    this->networkService = networkService;
    this->cryptoService = cryptoService;
    this->noiseService = noiseService;

    // clang-format off
    networkService->setPacketReceivedCallback([this](const BitchatPacket &packet, const std::string &peripheralID) {
        processPacket(packet, peripheralID);
    });
    // clang-format on

    // clang-format off
    networkService->setPeerConnectedCallback([this](const std::string &peripheralID) {
        peerConnected(peripheralID);
    });
    // clang-format on

    // clang-format off
    networkService->setPeerDisconnectedCallback([this](const std::string &peripheralID) {
        peerDisconnected(peripheralID);
    });
    // clang-format on

    spdlog::info("MessageService initialized");

    return true;
}

bool MessageService::sendMessage(const std::string &content, const std::string &channel)
{
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
    BitchatData::shared()->setCurrentChannel(channel);

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

    BitchatData::shared()->setCurrentChannel("");

    // Send channel leave packet
    BitchatPacket packet = createChannelAnnouncePacket("", false);
    networkService->sendPacket(packet);

    if (channelLeftCallback)
    {
        channelLeftCallback(currentChannel);
    }

    spdlog::info("Left channel: {}", currentChannel);
}

void MessageService::startIdentityAnnounce()
{
    if (!noiseService || !cryptoService)
    {
        spdlog::error("Cannot send noise identity announce because services not available");
        return;
    }

    // Create identity announcement payload
    std::vector<uint8_t> payload;
    std::string peerID = BitchatData::shared()->getPeerID();
    payload.insert(payload.end(), peerID.begin(), peerID.end());
    BitchatPacket packet(PKT_TYPE_NOISE_IDENTITY_ANNOUNCE, payload);
    packet.setSenderID(StringHelper::stringToVector(BitchatData::shared()->getPeerID()));
    packet.setTimestamp(DateTimeHelper::getCurrentTimestamp());

    networkService->sendPacket(packet);
    spdlog::info("Sent Noise identity announce");
}

void MessageService::peerJoined(const std::string &peerID, const std::string &nickname)
{
    if (peerJoinedCallback)
    {
        peerJoinedCallback(peerID, nickname);
    }
}

void MessageService::peerLeft(const std::string &peerID, const std::string &nickname)
{
    if (peerLeftCallback)
    {
        peerLeftCallback(peerID, nickname);
    }
}

void MessageService::peerConnected(const std::string &peripheralID)
{
    if (peerConnectedCallback)
    {
        peerConnectedCallback(peripheralID);
    }
}

void MessageService::peerDisconnected(const std::string &peripheralID)
{
    // Remove peer from data store
    auto peers = BitchatData::shared()->getPeers();

    for (const auto &peer : peers)
    {
        if (peer.getPeripheralID() == peripheralID)
        {
            std::string peerID = peer.getPeerID();
            std::string nickname = peer.getNickname();
            BitchatData::shared()->removePeer(peerID);

            peerLeft(peerID, nickname);

            break;
        }
    }

    if (peerDisconnectedCallback)
    {
        peerDisconnectedCallback(peripheralID);
    }
}

void MessageService::processPacket(const BitchatPacket &packet, const std::string &peripheralID)
{
    // Validate packet
    if (!packet.isValid())
    {
        spdlog::warn("Received invalid packet from {}", StringHelper::toHex(packet.getSenderID()));
        return;
    }

    // Check if we should process this packet
    if (!shouldProcessPacket(packet))
    {
        return;
    }

    // Mark packet as processed
    markPacketProcessed(packet);

    // Route to appropriate processor based on packet type

    switch (packet.getType())
    {
    case PKT_TYPE_MESSAGE:
        processMessagePacket(packet);
        break;
    case PKT_TYPE_CHANNEL_ANNOUNCE:
        processChannelAnnouncePacket(packet);
        break;
    case PKT_TYPE_ANNOUNCE:
        processAnnouncePacket(packet, peripheralID);
        break;
    case PKT_TYPE_LEAVE:
        processLeavePacket(packet);
        break;
    case PKT_TYPE_NOISE_HANDSHAKE_INIT:
        processNoiseHandshakeInitPacket(packet);
        break;
    case PKT_TYPE_NOISE_HANDSHAKE_RESP:
        processNoiseHandshakeRespPacket(packet);
        break;
    case PKT_TYPE_NOISE_ENCRYPTED:
        processNoiseEncryptedPacket(packet);
        break;
    case PKT_TYPE_NOISE_IDENTITY_ANNOUNCE:
        processNoiseIdentityAnnouncePacket(packet);
        break;
    default:
        spdlog::debug("Unhandled packet type: {}", packet.getTypeString());
        break;
    }
}

void MessageService::processMessagePacket(const BitchatPacket &packet)
{
    PacketSerializer serializer;
    BitchatMessage message = serializer.parseMessagePayload(packet.getPayload());

    spdlog::debug("Processing message packet - ID: {}, Sender: {}, Content: {}, Channel: {}, Private: {}", message.getId(), message.getSender(), message.getContent(), message.getChannel(), message.isPrivate());

    // Ignore messages from ourselves to prevent duplication
    std::string senderID = StringHelper::toHex(packet.getSenderID());
    std::string localPeerID = BitchatData::shared()->getPeerID();
    spdlog::debug("Message sender ID: {}, Local peer ID: {}", senderID, localPeerID);

    if (senderID == localPeerID)
    {
        spdlog::debug("Ignoring message from ourselves: {}", senderID);
        return;
    }

    // Add to history if it's for our current channel, default chat (empty channel), or a private message
    bool shouldAddToHistory = false;

    std::string currentChannel = BitchatData::shared()->getCurrentChannel();

    if (message.getChannel() == currentChannel)
    {
        spdlog::debug("Message is for current channel: '{}'", currentChannel);
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

        if (messageReceivedCallback)
        {
            messageReceivedCallback(message);
        }

        spdlog::debug("Added message to history");
    }

    spdlog::debug("Processed message from: {}", message.getSender());
}

void MessageService::processChannelAnnouncePacket(const BitchatPacket &packet)
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

void MessageService::processAnnouncePacket(const BitchatPacket &packet, const std::string &peripheralID)
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
    }
    else
    {
        // Add new peer
        BitchatPeer peer(peerID, nickname);
        peer.updateLastSeen();
        peer.setPeripheralID(peripheralID);
        peer.setHasAnnounced(true);
        BitchatData::shared()->addPeer(peer);

        if (peerJoinedCallback)
        {
            peerJoinedCallback(peerID, nickname);
        }

        spdlog::debug("Added new peer: {} ({})", peerID, nickname);
    }
}

void MessageService::processLeavePacket(const BitchatPacket &packet)
{
    std::string peerID = StringHelper::toHex(packet.getSenderID());
    auto peerInfo = BitchatData::shared()->getPeerInfo(peerID);

    if (peerInfo)
    {
        std::string nickname = peerInfo->getNickname();
        BitchatData::shared()->removePeer(peerID);

        if (peerLeftCallback)
        {
            peerLeftCallback(peerID, nickname);
        }

        spdlog::debug("Processed leave packet from {} ({})", nickname, peerID);
    }
}

void MessageService::processNoiseHandshakeInitPacket(const BitchatPacket &packet)
{
    if (!noiseService)
    {
        spdlog::warn("Noise Service not available");
        return;
    }

    std::string peerID = StringHelper::toHex(packet.getSenderID());

    // Ignore packets from ourselves to prevent echo loops
    if (peerID == BitchatData::shared()->getPeerID())
    {
        spdlog::debug("Ignoring Noise packet from ourselves: {}", peerID);
        return;
    }

    spdlog::info("=== RECEIVED NOISE_HANDSHAKE_INIT ===");
    spdlog::info("From peerID: '{}' (size: {})", peerID, peerID.size());
    spdlog::info("Payload size: {} bytes", packet.getPayload().size());
    spdlog::info("Local peerID: '{}' (size: {})", BitchatData::shared()->getPeerID(), BitchatData::shared()->getPeerID().size());

    // Check if session is already established
    if (noiseService->hasEstablishedSession(peerID))
    {
        spdlog::debug("Ignoring handshake init from {} - session already established", peerID);
        return;
    }

    auto response = noiseService->handleIncomingHandshake(peerID, packet.getPayload(), BitchatData::shared()->getPeerID());
    if (response.has_value() && !response->empty())
    {
        spdlog::info("=== SENDING NOISE_HANDSHAKE_RESP ===");
        spdlog::info("To peerID: '{}'", peerID);
        spdlog::info("Response size: {} bytes", response->size());

        // Send handshake response
        BitchatPacket responsePacket(PKT_TYPE_NOISE_HANDSHAKE_RESP, *response);
        responsePacket.setSenderID(StringHelper::stringToVector(BitchatData::shared()->getPeerID()));
        responsePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());
        networkService->sendPacket(responsePacket);
        spdlog::info("Sent Noise handshake response to {}", peerID);
    }
    else
    {
        spdlog::info("No handshake response needed for {}", peerID);
    }
}

void MessageService::processNoiseHandshakeRespPacket(const BitchatPacket &packet)
{
    if (!noiseService)
    {
        spdlog::warn("Noise Service not available");
        return;
    }

    std::string peerID = StringHelper::toHex(packet.getSenderID());

    // Ignore packets from ourselves to prevent echo loops
    if (peerID == BitchatData::shared()->getPeerID())
    {
        spdlog::debug("Ignoring Noise packet from ourselves: {}", peerID);
        return;
    }

    spdlog::info("=== RECEIVED NOISE_HANDSHAKE_RESP ===");
    spdlog::info("From peerID: '{}' (size: {})", peerID, peerID.size());
    spdlog::info("Payload size: {} bytes", packet.getPayload().size());
    spdlog::info("Local peerID: '{}' (size: {})", BitchatData::shared()->getPeerID(), BitchatData::shared()->getPeerID().size());

    // Determine if we are initiator or responder based on peerID comparison
    std::string localPeerID = BitchatData::shared()->getPeerID();
    bool isInitiator = localPeerID < peerID;
    spdlog::info("Our role: {} (localPeerID: '{}' vs remotePeerID: '{}')", isInitiator ? "INITIATOR" : "RESPONDER", localPeerID, peerID);

    // Check if session is already established
    if (noiseService->hasEstablishedSession(peerID))
    {
        spdlog::debug("Ignoring handshake response from {} - session already established", peerID);
        return;
    }

    spdlog::info("=== CALLING handleIncomingHandshake ===");
    spdlog::info("PeerID: '{}'", peerID);
    spdlog::info("Payload size: {} bytes", packet.getPayload().size());

    // Log payload hex for debugging
    std::string payloadHex;
    for (size_t i = 0; i < std::min(size_t(32), packet.getPayload().size()); ++i)
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", packet.getPayload()[i]);
        payloadHex += hex;
    }
    spdlog::info("Payload (first 32 bytes): {}", payloadHex);

    auto response = noiseService->handleIncomingHandshake(peerID, packet.getPayload(), BitchatData::shared()->getPeerID());
    spdlog::info("handleIncomingHandshake returned response: has_value={}, empty={}, size={}",
                 response.has_value(), response.has_value() ? response->empty() : true,
                 response.has_value() ? response->size() : 0);

    // Log the expected flow
    if (response.has_value() && !response->empty())
    {
        if (response->size() == 96)
        {
            spdlog::info("CRITICAL: Received 96-byte response - this should be from responder to initiator");
            spdlog::info("This should trigger sending 48-byte final message");
        }
        else if (response->size() == 48)
        {
            spdlog::info("CRITICAL: Received 48-byte response - this should be from initiator to responder");
            spdlog::info("This should complete the handshake");
        }
    }

    if (response.has_value() && !response->empty())
    {
        if (response->size() == 96)
        {
            // responder to initiator (first response in XX handshake)
            // (should occur on responder side, rarely here)
            spdlog::info("=== SENDING 96-BYTE RESPONSE ===");
            spdlog::info("To peerID: '{}'", peerID);
            spdlog::info("This should only happen on responder side");
            BitchatPacket responsePacket(PKT_TYPE_NOISE_HANDSHAKE_RESP, *response);
            responsePacket.setSenderID(StringHelper::stringToVector(BitchatData::shared()->getPeerID()));
            responsePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());
            networkService->sendPacket(responsePacket);
            spdlog::info("Sent 96-byte handshake response to {}", peerID);
        }
        else if (response->size() == 48)
        {
            // initiator final message to responder (this was missing!)
            spdlog::info("=== SENDING 48-BYTE FINAL MESSAGE ===");
            spdlog::info("To peerID: '{}'", peerID);
            spdlog::info("This should complete the handshake on the responder side");
            spdlog::info("This is the FINAL message from initiator to responder");
            spdlog::info("After this, handshake should be complete on both sides");

            BitchatPacket responsePacket(PKT_TYPE_NOISE_HANDSHAKE_RESP, *response);
            responsePacket.setSenderID(StringHelper::stringToVector(BitchatData::shared()->getPeerID()));
            responsePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());
            networkService->sendPacket(responsePacket);
            spdlog::info("Sent 48-byte final handshake message to {}", peerID);
            spdlog::info("Handshake should now be complete on initiator side");
        }
        else
        {
            spdlog::warn("Unexpected handshake response size: {}, not sending further response", response->size());
        }
    }
    else if (!response.has_value() || response->empty())
    {
        spdlog::info("=== NOISE SESSION ESTABLISHED ===");
        spdlog::info("With peerID: '{}'", peerID);
        spdlog::info("No more handshake messages needed");
        spdlog::info("Session is now ready for encrypted communication");
    }
}

void MessageService::processNoiseEncryptedPacket(const BitchatPacket &packet)
{
    if (!noiseService)
    {
        spdlog::warn("Noise Service not available");
        return;
    }

    std::string peerID = StringHelper::toHex(packet.getSenderID());

    // Ignore packets from ourselves to prevent echo loops
    if (peerID == BitchatData::shared()->getPeerID())
    {
        spdlog::debug("Ignoring Noise packet from ourselves: {}", peerID);
        return;
    }

    spdlog::info("=== RECEIVED NOISE_ENCRYPTED ===");
    spdlog::info("From peerID: '{}' (size: {})", peerID, peerID.size());
    spdlog::info("Payload size: {} bytes", packet.getPayload().size());

    auto decryptedPayload = noiseService->decrypt(packet.getPayload(), peerID);
    if (!decryptedPayload.empty())
    {
        spdlog::info("Successfully decrypted message from {}", peerID);
        spdlog::info("Decrypted payload size: {} bytes", decryptedPayload.size());

        // Create a new packet with decrypted payload and process it
        BitchatPacket decryptedPacket(PKT_TYPE_MESSAGE, decryptedPayload);
        decryptedPacket.setSenderID(packet.getSenderID());
        decryptedPacket.setTimestamp(packet.getTimestamp());
        decryptedPacket.setFlags(packet.getFlags());

        // Process the decrypted message
        processMessagePacket(decryptedPacket);
    }
    else
    {
        spdlog::warn("Failed to decrypt message from {}", peerID);
    }
}

void MessageService::processNoiseIdentityAnnouncePacket(const BitchatPacket &packet)
{
    if (!noiseService)
    {
        spdlog::warn("Noise Service not available");
        return;
    }

    std::string peerID = StringHelper::toHex(packet.getSenderID());

    // Ignore packets from ourselves to prevent echo loops
    if (peerID == BitchatData::shared()->getPeerID())
    {
        spdlog::debug("Ignoring Noise packet from ourselves: {}", peerID);
        return;
    }

    spdlog::info("=== RECEIVED NOISE IDENTITY ANNOUNCE ===");
    spdlog::info("From peerID: '{}'", peerID);

    std::string localPeerID = BitchatData::shared()->getPeerID();

    // Use robust handshake strategy: prefer to initiate if we have smaller peerID
    if (localPeerID < peerID)
    {
        spdlog::info("Preferring to initiate handshake with {} (our peerID {} < their peerID {})", peerID, localPeerID, peerID);
        // Get handshake data and send
        auto handshakeData = noiseService->initiateHandshake(peerID);
        if (!handshakeData.empty())
        {
            spdlog::info("=== SENDING NOISE HANDSHAKE INIT ===");
            spdlog::info("To peerID: '{}'", peerID);
            spdlog::info("Handshake data size: {} bytes", handshakeData.size());

            BitchatPacket handshakePacket(PKT_TYPE_NOISE_HANDSHAKE_INIT, handshakeData);
            handshakePacket.setSenderID(StringHelper::stringToVector(BitchatData::shared()->getPeerID()));
            handshakePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());
            networkService->sendPacket(handshakePacket);
            spdlog::info("Sent Noise handshake init to {}", peerID);
        }
        else
        {
            spdlog::warn("No handshake data generated for {}", peerID);
        }
    }
    else
    {
        spdlog::info("Preferring to wait for handshake from {} (their peerID {} < our peerID {})", peerID, peerID, localPeerID);
        // Don't wait forever - if no handshake comes, we can still initiate later
    }
}

bool MessageService::shouldProcessPacket(const BitchatPacket &packet) const
{
    // Check if we've already processed this message
    std::string messageID = StringHelper::toHex(packet.getSenderID()) + "_" + std::to_string(packet.getTimestamp());

    if (BitchatData::shared()->wasMessageProcessed(messageID))
    {
        spdlog::debug("Packet already processed, skipping: {}", messageID);
        return false;
    }

    return true;
}

void MessageService::markPacketProcessed(const BitchatPacket &packet)
{
    std::string messageID = StringHelper::toHex(packet.getSenderID()) + "_" + std::to_string(packet.getTimestamp());
    BitchatData::shared()->markMessageProcessed(messageID);
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

    if (noiseService && !message.isPrivate())
    {
        // For channel messages, check if we have any established sessions
        auto establishedSessionIDs = noiseService->getEstablishedSessionIDs();
        if (!establishedSessionIDs.empty())
        {
            // Use the first established session for encryption
            auto firstPeerId = establishedSessionIDs[0];

            auto encryptedPayload = noiseService->encrypt(payload, firstPeerId);

            // Use encrypted packet type
            packetType = PKT_TYPE_NOISE_ENCRYPTED;
            payload = encryptedPayload;

            spdlog::debug("Message encrypted with Noise protocol for peer: {}", firstPeerId);
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

void MessageService::setPeerJoinedCallback(PeerJoinedCallback callback)
{
    peerJoinedCallback = callback;
}

void MessageService::setPeerLeftCallback(PeerLeftCallback callback)
{
    peerLeftCallback = callback;
}

void MessageService::setPeerConnectedCallback(PeerConnectedCallback callback)
{
    peerConnectedCallback = callback;
}

void MessageService::setPeerDisconnectedCallback(PeerDisconnectedCallback callback)
{
    peerDisconnectedCallback = callback;
}

} // namespace bitchat
