#include "bitchat/core/bitchat_manager.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/protocol_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/platform/bluetooth_factory.h"
#include "bitchat/protocol/packet.h"
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

namespace bitchat
{

BitchatManager::BitchatManager()
{
}

BitchatManager::~BitchatManager()
{
    stop();
}

bool BitchatManager::initialize()
{
    if (initialized)
    {
        spdlog::warn("BitchatManager already initialized");
        return true;
    }

    try
    {
        // Generate local peer ID
        std::string localPeerID = StringHelper::randomPeerID();
        spdlog::info("Generated local peer ID: {}", localPeerID);

        // Create Bluetooth interface
        bluetoothInterface = createBluetoothInterface();

        if (!bluetoothInterface)
        {
            spdlog::error("Failed to create Bluetooth interface");
            return false;
        }

        // Create managers
        networkManager = std::make_shared<NetworkManager>();
        messageManager = std::make_shared<MessageManager>();
        cryptoManager = std::make_shared<CryptoManager>();
        compressionManager = std::make_shared<CompressionManager>();

        // Initialize managers
        if (!networkManager->initialize(bluetoothInterface))
        {
            spdlog::error("Failed to initialize NetworkManager");
            return false;
        }

        // Set the local peer ID
        networkManager->setLocalPeerID(localPeerID);

        if (!cryptoManager->initialize())
        {
            spdlog::error("Failed to initialize CryptoManager");
            return false;
        }

        // Generate or load key pair
        if (!cryptoManager->generateOrLoadKeyPair("bitchat-pk.pem"))
        {
            spdlog::error("Failed to generate or load key pair");
            return false;
        }

        // Initialize Noise Session Manager with Curve25519 key
        try
        {
            std::vector<uint8_t> noiseKey = cryptoManager->getCurve25519PrivateKey();

            if (noiseKey.size() != 32)
            {
                spdlog::error("Invalid Curve25519 key size for Noise");
                return false;
            }

            // Debug: Log key information
            spdlog::info("=== NOISE KEY DEBUG ===");
            spdlog::info("Private key size: {} bytes", noiseKey.size());

            // Convert to hex for logging
            std::string privKeyHex;

            for (size_t i = 0; i < std::min(size_t(16), noiseKey.size()); ++i)
            {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", noiseKey[i]);
                privKeyHex += hex;
            }

            spdlog::info("Private key (first 16 bytes): {}", privKeyHex);

            // Calculate public key from private key using OpenSSL
            std::vector<uint8_t> pubKey(32);

            EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, noiseKey.data(), noiseKey.size());

            if (pkey)
            {
                size_t pubKeyLen = pubKey.size();
                if (EVP_PKEY_get_raw_public_key(pkey, pubKey.data(), &pubKeyLen) == 1)
                {
                    std::string pubKeyHex;
                    for (size_t i = 0; i < std::min(size_t(16), pubKey.size()); ++i)
                    {
                        char hex[3];
                        snprintf(hex, sizeof(hex), "%02x", pubKey[i]);
                        pubKeyHex += hex;
                    }
                    spdlog::info("Public key (first 16 bytes): {}", pubKeyHex);
                }
                else
                {
                    spdlog::error("Failed to extract public key from private key");
                }

                EVP_PKEY_free(pkey);
            }
            else
            {
                spdlog::error("Failed to create EVP_PKEY from private key");
            }

            spdlog::info("Local PeerID: '{}' (size: {})", networkManager->getLocalPeerID(), networkManager->getLocalPeerID().size());
            spdlog::info("=== END NOISE KEY DEBUG ===");

            noise::PrivateKey privateKey;
            std::copy(noiseKey.begin(), noiseKey.end(), privateKey.begin());
            spdlog::debug("Noise private key size: {}", privateKey.size());
            noiseSessionManager = std::make_shared<noise::NoiseSessionManager>(privateKey);
            spdlog::info("Noise Session Manager initialized");
        }
        catch (const std::exception &e)
        {
            spdlog::error("Failed to initialize Noise Session Manager: {}", e.what());
            return false;
        }

        if (!messageManager->initialize(networkManager, cryptoManager, compressionManager, noiseSessionManager))
        {
            spdlog::error("Failed to initialize MessageManager");
            return false;
        }

        // Send initial Noise identity announce
        sendNoiseIdentityAnnounce();

        if (!compressionManager)
        {
            spdlog::error("Failed to create CompressionManager");
            return false;
        }

        // Set up callbacks
        setupCallbacks();

        // Sync nickname from MessageManager to NetworkManager
        networkManager->setNickname(messageManager->getNickname());

        initialized = true;
        spdlog::info("BitchatManager initialized successfully");
        return true;
    }
    catch (const std::exception &e)
    {
        spdlog::error("Exception during initialization: {}", e.what());
        return false;
    }
}

bool BitchatManager::start()
{
    if (!initialized)
    {
        spdlog::error("BitchatManager not initialized");
        return false;
    }

    if (started)
    {
        spdlog::warn("BitchatManager already started");
        return true;
    }

    try
    {
        if (!networkManager->start())
        {
            spdlog::error("Failed to start NetworkManager");
            return false;
        }

        started = true;
        spdlog::info("BitchatManager started successfully");
        return true;
    }
    catch (const std::exception &e)
    {
        spdlog::error("Exception during start: {}", e.what());
        return false;
    }
}

void BitchatManager::stop()
{
    if (!started)
    {
        return;
    }

    try
    {
        networkManager->stop();
        started = false;
        spdlog::info("BitchatManager stopped");
    }
    catch (const std::exception &e)
    {
        spdlog::error("Exception during stop: {}", e.what());
    }
}

bool BitchatManager::sendMessage(const std::string &content)
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return false;
    }

    return messageManager->sendMessage(content);
}

bool BitchatManager::sendPrivateMessage(const std::string &content, const std::string &recipientNickname)
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return false;
    }

    return messageManager->sendPrivateMessage(content, recipientNickname);
}

void BitchatManager::joinChannel(const std::string &channel)
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return;
    }

    messageManager->joinChannel(channel);
}

void BitchatManager::leaveChannel()
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return;
    }

    messageManager->leaveChannel();
}

void BitchatManager::setNickname(const std::string &nickname)
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return;
    }

    messageManager->setNickname(nickname);
}

std::string BitchatManager::getCurrentChannel() const
{
    if (!messageManager)
    {
        return "";
    }
    return messageManager->getCurrentChannel();
}

std::string BitchatManager::getNickname() const
{
    if (!messageManager)
    {
        return "";
    }
    return messageManager->getNickname();
}

std::string BitchatManager::getPeerID() const
{
    if (!networkManager)
    {
        return "";
    }
    return networkManager->getLocalPeerID();
}

void BitchatManager::setPeerID(const std::string &peerID)
{
    if (!networkManager)
    {
        spdlog::error("Cannot set peer ID: NetworkManager not initialized");
        return;
    }

    if (!ProtocolHelper::isValidPeerID(peerID))
    {
        spdlog::error("Invalid peer ID format: {}", peerID);
        return;
    }

    networkManager->setLocalPeerID(peerID);
}

std::map<std::string, BitchatPeer> BitchatManager::getOnlinePeers() const
{
    if (!networkManager)
    {
        return {};
    }
    return networkManager->getOnlinePeers();
}

std::vector<BitchatMessage> BitchatManager::getMessageHistory() const
{
    if (!messageManager)
    {
        return {};
    }
    return messageManager->getMessageHistory();
}

size_t BitchatManager::getConnectedPeersCount() const
{
    if (!networkManager)
    {
        return 0;
    }
    return networkManager->getConnectedPeersCount();
}

bool BitchatManager::isReady() const
{
    return initialized && started && networkManager && messageManager && networkManager->isReady() && messageManager->isReady();
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

void BitchatManager::setupCallbacks()
{
    // Set up message manager callbacks
    // clang-format off
    messageManager->setMessageReceivedCallback([this](const BitchatMessage &message) {
        onMessageReceived(message);
    });
    // clang-format on

    // Set up network manager callbacks
    // clang-format off
    networkManager->setPeerConnectedCallback([this](const std::string &peerID, const std::string &nickname) {
        onPeerJoined(peerID, nickname);
    });
    // clang-format on

    // clang-format off
    networkManager->setPeerDisconnectedCallback([this](const std::string &peerID, const std::string &nickname) {
        onPeerLeft(peerID, nickname);
    });
    // clang-format on

    // Process all packets from NetworkManager
    // clang-format off
    networkManager->setPacketReceivedCallback([this](const BitchatPacket &packet) {
        switch (packet.getType())
        {
        case PKT_TYPE_MESSAGE:
            // Forward to MessageManager for normal messages
            spdlog::debug("Received message packet from {}", StringHelper::toHex(packet.getSenderID()));
            messageManager->processPacket(packet);
            break;
        case PKT_TYPE_NOISE_HANDSHAKE_INIT:
        case PKT_TYPE_NOISE_HANDSHAKE_RESP:
        case PKT_TYPE_NOISE_ENCRYPTED:
        case PKT_TYPE_NOISE_IDENTITY_ANNOUNCE:
            // Process Noise packets
            processNoisePacket(packet);
            break;
        default:
            // Other packet types are handled by NetworkManager
            break;
        }
    });
    // clang-format on
}

void BitchatManager::onMessageReceived(const BitchatMessage &message)
{
    if (messageCallback)
    {
        messageCallback(message);
    }
}

void BitchatManager::onPeerJoined(const std::string &peerID, const std::string &nickname)
{
    if (peerJoinedCallback)
    {
        peerJoinedCallback(peerID, nickname);
    }
}

void BitchatManager::onPeerLeft(const std::string &peerID, const std::string &nickname)
{
    if (peerLeftCallback)
    {
        peerLeftCallback(peerID, nickname);
    }
}

void BitchatManager::onStatusUpdate(const std::string &status)
{
    if (statusCallback)
    {
        statusCallback(status);
    }
}

void BitchatManager::processNoisePacket(const BitchatPacket &packet)
{
    if (!noiseSessionManager)
    {
        spdlog::warn("Noise Session Manager not available");
        return;
    }

    std::string peerID = StringHelper::toHex(packet.getSenderID());

    // Ignore packets from ourselves to prevent echo loops
    if (peerID == networkManager->getLocalPeerID())
    {
        spdlog::debug("Ignoring Noise packet from ourselves: {}", peerID);
        return;
    }

    try
    {
        switch (packet.getType())
        {
        case PKT_TYPE_NOISE_HANDSHAKE_INIT:
        {
            spdlog::info("=== RECEIVED NOISE_HANDSHAKE_INIT ===");
            spdlog::info("From peerID: '{}' (size: {})", peerID, peerID.size());
            spdlog::info("Payload size: {} bytes", packet.getPayload().size());
            spdlog::info("Local peerID: '{}' (size: {})", networkManager->getLocalPeerID(), networkManager->getLocalPeerID().size());
            try
            {
                // Check if session is already established
                if (noiseSessionManager->hasEstablishedSession(peerID))
                {
                    spdlog::debug("Ignoring handshake init from {} - session already established", peerID);
                    break;
                }

                auto response = noiseSessionManager->handleIncomingHandshake(peerID, packet.getPayload(), networkManager->getLocalPeerID());
                if (response.has_value() && !response->empty())
                {
                    spdlog::info("=== SENDING NOISE_HANDSHAKE_RESP ===");
                    spdlog::info("To peerID: '{}'", peerID);
                    spdlog::info("Response size: {} bytes", response->size());

                    // Send handshake response
                    BitchatPacket responsePacket(PKT_TYPE_NOISE_HANDSHAKE_RESP, *response);
                    responsePacket.setSenderID(StringHelper::stringToVector(networkManager->getLocalPeerID()));
                    responsePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());
                    networkManager->sendPacket(responsePacket);
                    spdlog::info("Sent Noise handshake response to {}", peerID);
                }
                else
                {
                    spdlog::info("No handshake response needed for {}", peerID);
                }
            }
            catch (const std::exception &e)
            {
                spdlog::error("Failed to handle handshake init from {}: {}", peerID, e.what());
            }
            break;
        }
        case PKT_TYPE_NOISE_HANDSHAKE_RESP:
        {
            spdlog::info("=== RECEIVED NOISE_HANDSHAKE_RESP ===");
            spdlog::info("From peerID: '{}' (size: {})", peerID, peerID.size());
            spdlog::info("Payload size: {} bytes", packet.getPayload().size());
            spdlog::info("Local peerID: '{}' (size: {})", networkManager->getLocalPeerID(), networkManager->getLocalPeerID().size());

            // Determine if we are initiator or responder based on peerID comparison
            std::string localPeerID = networkManager->getLocalPeerID();
            bool isInitiator = localPeerID < peerID;
            spdlog::info("Our role: {} (localPeerID: '{}' vs remotePeerID: '{}')",
                         isInitiator ? "INITIATOR" : "RESPONDER", localPeerID, peerID);
            try
            {
                // Check if session is already established
                if (noiseSessionManager->hasEstablishedSession(peerID))
                {
                    spdlog::debug("Ignoring handshake response from {} - session already established", peerID);
                    break;
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

                auto response = noiseSessionManager->handleIncomingHandshake(peerID, packet.getPayload(), networkManager->getLocalPeerID());
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
                        responsePacket.setSenderID(StringHelper::stringToVector(networkManager->getLocalPeerID()));
                        responsePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());
                        networkManager->sendPacket(responsePacket);
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
                        responsePacket.setSenderID(StringHelper::stringToVector(networkManager->getLocalPeerID()));
                        responsePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());
                        networkManager->sendPacket(responsePacket);
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
            catch (const std::exception &e)
            {
                spdlog::error("Failed to handle handshake response from {}: {}", peerID, e.what());
            }
            break;
        }
        case PKT_TYPE_NOISE_ENCRYPTED:
        {
            spdlog::info("Received Noise encrypted message from {}", peerID);
            try
            {
                auto decrypted = noiseSessionManager->decrypt(packet.getPayload(), peerID);
                // Process decrypted message
                spdlog::info("Decrypted message from {}: {}", peerID, std::string(decrypted.begin(), decrypted.end()));
            }
            catch (const std::exception &e)
            {
                spdlog::error("Failed to decrypt Noise message from {}: {}", peerID, e.what());
            }
            break;
        }
        case PKT_TYPE_NOISE_IDENTITY_ANNOUNCE:
        {
            spdlog::info("=== RECEIVED NOISE IDENTITY ANNOUNCE ===");
            spdlog::info("From peerID: '{}'", peerID);

            try
            {
                std::string localPeerID = networkManager->getLocalPeerID();

                // Use robust handshake strategy: prefer to initiate if we have smaller peerID
                if (localPeerID < peerID)
                {
                    spdlog::info("Preferring to initiate handshake with {} (our peerID {} < their peerID {})",
                                 peerID, localPeerID, peerID);
                    try
                    {
                        // Get handshake data and send
                        auto handshakeData = noiseSessionManager->initiateHandshake(peerID);
                        if (!handshakeData.empty())
                        {
                            spdlog::info("=== SENDING NOISE HANDSHAKE INIT ===");
                            spdlog::info("To peerID: '{}'", peerID);
                            spdlog::info("Handshake data size: {} bytes", handshakeData.size());

                            BitchatPacket handshakePacket(PKT_TYPE_NOISE_HANDSHAKE_INIT, handshakeData);
                            handshakePacket.setSenderID(StringHelper::stringToVector(localPeerID));
                            handshakePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());
                            networkManager->sendPacket(handshakePacket);
                            spdlog::info("Sent Noise handshake init to {}", peerID);
                        }
                        else
                        {
                            spdlog::warn("No handshake data generated for {}", peerID);
                        }
                    }
                    catch (const std::exception &e)
                    {
                        spdlog::error("Failed to initiate handshake with {}: {}", peerID, e.what());
                    }
                }
                else
                {
                    spdlog::info("Preferring to wait for handshake from {} (their peerID {} < our peerID {})",
                                 peerID, peerID, localPeerID);
                    // Don't wait forever - if no handshake comes, we can still initiate later
                }
            }
            catch (const std::exception &e)
            {
                spdlog::error("Failed to process identity announce from {}: {}", peerID, e.what());
            }
            break;
        }
        default:
            break;
        }
    }
    catch (const std::exception &e)
    {
        spdlog::error("Error processing Noise packet from {}: {}", peerID, e.what());
    }
}

void BitchatManager::sendNoiseIdentityAnnounce()
{
    if (!noiseSessionManager || !cryptoManager)
    {
        spdlog::warn("Cannot send Noise identity announce - managers not available");
        return;
    }

    try
    {
        // Create simple identity announcement payload
        std::vector<uint8_t> payload;
        std::string peerID = networkManager->getLocalPeerID();
        payload.insert(payload.end(), peerID.begin(), peerID.end());
        BitchatPacket packet(PKT_TYPE_NOISE_IDENTITY_ANNOUNCE, payload);
        packet.setSenderID(StringHelper::stringToVector(networkManager->getLocalPeerID()));
        packet.setTimestamp(DateTimeHelper::getCurrentTimestamp());

        networkManager->sendPacket(packet);
        spdlog::info("Sent Noise identity announce");
    }
    catch (const std::exception &e)
    {
        spdlog::error("Failed to send Noise identity announce: {}", e.what());
    }
}

} // namespace bitchat
