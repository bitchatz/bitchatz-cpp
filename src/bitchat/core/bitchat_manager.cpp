#include "bitchat/core/bitchat_manager.h"
#include "bitchat/helpers/datetime_helper.h"
#include "bitchat/helpers/protocol_helper.h"
#include "bitchat/helpers/string_helper.h"
#include "bitchat/platform/bluetooth_factory.h"
#include "bitchat/protocol/packet.h"
#include "bitchat/runners/bluetooth_announce_runner.h"
#include "bitchat/runners/cleanup_runner.h"
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

bool BitchatManager::initialize(std::shared_ptr<BluetoothAnnounceRunner> announceRunner, std::shared_ptr<CleanupRunner> cleanupRunner)
{
    if (initialized)
    {
        spdlog::warn("BitchatManager already initialized");
        return true;
    }

    // Store runners
    this->announceRunner = announceRunner;
    this->cleanupRunner = cleanupRunner;

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

        // Create services
        networkService = std::make_shared<NetworkService>();
        messageService = std::make_shared<MessageService>();
        cryptoService = std::make_shared<CryptoService>();

        // Set runners in NetworkService before initialization
        if (announceRunner)
        {
            networkService->setAnnounceRunner(announceRunner);
        }

        if (cleanupRunner)
        {
            networkService->setCleanupRunner(cleanupRunner);
        }

        // Initialize managers
        if (!networkService->initialize(bluetoothInterface))
        {
            spdlog::error("Failed to initialize NetworkService");
            return false;
        }

        // Set the local peer ID
        networkService->setLocalPeerID(localPeerID);

        if (!cryptoService->initialize())
        {
            spdlog::error("Failed to initialize CryptoService");
            return false;
        }

        // Generate or load key pair
        if (!cryptoService->generateOrLoadKeyPair("bitchat-pk.pem"))
        {
            spdlog::error("Failed to generate or load key pair");
            return false;
        }

        // Initialize Noise Session Manager with Curve25519 key
        try
        {
            std::vector<uint8_t> noiseKey = cryptoService->getCurve25519PrivateKey();

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

            spdlog::info("Local PeerID: '{}' (size: {})", networkService->getLocalPeerID(), networkService->getLocalPeerID().size());
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

        if (!messageService->initialize(networkService, cryptoService, noiseSessionManager))
        {
            spdlog::error("Failed to initialize MessageService");
            return false;
        }

        // Send initial Noise identity announce
        sendNoiseIdentityAnnounce();

        // Set up callbacks
        setupCallbacks();

        // Sync nickname from MessageService to NetworkService
        networkService->setNickname(messageService->getNickname());

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
        if (!networkService->start())
        {
            spdlog::error("Failed to start NetworkService");
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
        networkService->stop();
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

    return messageService->sendMessage(content);
}

bool BitchatManager::sendPrivateMessage(const std::string &content, const std::string &recipientNickname)
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return false;
    }

    return messageService->sendPrivateMessage(content, recipientNickname);
}

void BitchatManager::joinChannel(const std::string &channel)
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return;
    }

    messageService->joinChannel(channel);
}

void BitchatManager::leaveChannel()
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return;
    }

    messageService->leaveChannel();
}

void BitchatManager::setNickname(const std::string &nickname)
{
    if (!isReady())
    {
        spdlog::error("BitchatManager not ready");
        return;
    }

    messageService->setNickname(nickname);
}

std::string BitchatManager::getCurrentChannel() const
{
    if (!messageService)
    {
        return "";
    }
    return messageService->getCurrentChannel();
}

std::string BitchatManager::getNickname() const
{
    if (!messageService)
    {
        return "";
    }
    return messageService->getNickname();
}

std::string BitchatManager::getPeerID() const
{
    if (!networkService)
    {
        return "";
    }
    return networkService->getLocalPeerID();
}

void BitchatManager::setPeerID(const std::string &peerID)
{
    if (!networkService)
    {
        spdlog::error("Cannot set peer ID: NetworkService not initialized");
        return;
    }

    if (!ProtocolHelper::isValidPeerID(peerID))
    {
        spdlog::error("Invalid peer ID format: {}", peerID);
        return;
    }

    networkService->setLocalPeerID(peerID);
}

std::vector<BitchatPeer> BitchatManager::getPeers() const
{
    if (!networkService)
    {
        return {};
    }

    return networkService->getPeers();
}

std::vector<BitchatMessage> BitchatManager::getMessageHistory() const
{
    if (!messageService)
    {
        return {};
    }
    return messageService->getMessageHistory();
}

size_t BitchatManager::getPeersCount() const
{
    if (!networkService)
    {
        return 0;
    }

    return networkService->getPeersCount();
}

bool BitchatManager::isReady() const
{
    return initialized && started && networkService && messageService && networkService->isReady() && messageService->isReady();
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
    messageService->setMessageReceivedCallback([this](const BitchatMessage &message) {
        onMessageReceived(message);
    });
    // clang-format on

    // Set up network manager callbacks
    // clang-format off
    networkService->setPeerConnectedCallback([]([[maybe_unused]] const std::string &uuid) {
        // Pass
    });
    // clang-format on

    // clang-format off
    networkService->setPeerDisconnectedCallback([this](const std::string &peerID, const std::string &nickname) {
        onPeerLeft(peerID, nickname);
    });
    // clang-format on

    // Process all packets from NetworkService
    // clang-format off
    networkService->setPacketReceivedCallback([this](const BitchatPacket &packet) {
        switch (packet.getType())
        {
        case PKT_TYPE_MESSAGE:
            // Forward to MessageService for normal messages
            spdlog::debug("Received message packet from {}", StringHelper::toHex(packet.getSenderID()));
            messageService->processPacket(packet);
            break;
        case PKT_TYPE_NOISE_HANDSHAKE_INIT:
        case PKT_TYPE_NOISE_HANDSHAKE_RESP:
        case PKT_TYPE_NOISE_ENCRYPTED:
        case PKT_TYPE_NOISE_IDENTITY_ANNOUNCE:
            // Process Noise packets
            processNoisePacket(packet);
            break;
        default:
            // Other packet types are handled by NetworkService
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
    if (peerID == networkService->getLocalPeerID())
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
            spdlog::info("Local peerID: '{}' (size: {})", networkService->getLocalPeerID(), networkService->getLocalPeerID().size());
            try
            {
                // Check if session is already established
                if (noiseSessionManager->hasEstablishedSession(peerID))
                {
                    spdlog::debug("Ignoring handshake init from {} - session already established", peerID);
                    break;
                }

                auto response = noiseSessionManager->handleIncomingHandshake(peerID, packet.getPayload(), networkService->getLocalPeerID());
                if (response.has_value() && !response->empty())
                {
                    spdlog::info("=== SENDING NOISE_HANDSHAKE_RESP ===");
                    spdlog::info("To peerID: '{}'", peerID);
                    spdlog::info("Response size: {} bytes", response->size());

                    // Send handshake response
                    BitchatPacket responsePacket(PKT_TYPE_NOISE_HANDSHAKE_RESP, *response);
                    responsePacket.setSenderID(StringHelper::stringToVector(networkService->getLocalPeerID()));
                    responsePacket.setTimestamp(DateTimeHelper::getCurrentTimestamp());
                    networkService->sendPacket(responsePacket);
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
            spdlog::info("Local peerID: '{}' (size: {})", networkService->getLocalPeerID(), networkService->getLocalPeerID().size());

            // Determine if we are initiator or responder based on peerID comparison
            std::string localPeerID = networkService->getLocalPeerID();
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

                auto response = noiseSessionManager->handleIncomingHandshake(peerID, packet.getPayload(), networkService->getLocalPeerID());
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
                        responsePacket.setSenderID(StringHelper::stringToVector(networkService->getLocalPeerID()));
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
                        responsePacket.setSenderID(StringHelper::stringToVector(networkService->getLocalPeerID()));
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
                std::string localPeerID = networkService->getLocalPeerID();

                // Use robust handshake strategy: prefer to initiate if we have smaller peerID
                if (localPeerID < peerID)
                {
                    spdlog::info("Preferring to initiate handshake with {} (our peerID {} < their peerID {})", peerID, localPeerID, peerID);
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
                            networkService->sendPacket(handshakePacket);
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
                    spdlog::info("Preferring to wait for handshake from {} (their peerID {} < our peerID {})", peerID, peerID, localPeerID);
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
    if (!noiseSessionManager || !cryptoService)
    {
        spdlog::warn("Cannot send Noise identity announce - managers not available");
        return;
    }

    try
    {
        // Create simple identity announcement payload
        std::vector<uint8_t> payload;
        std::string peerID = networkService->getLocalPeerID();
        payload.insert(payload.end(), peerID.begin(), peerID.end());
        BitchatPacket packet(PKT_TYPE_NOISE_IDENTITY_ANNOUNCE, payload);
        packet.setSenderID(StringHelper::stringToVector(networkService->getLocalPeerID()));
        packet.setTimestamp(DateTimeHelper::getCurrentTimestamp());

        networkService->sendPacket(packet);
        spdlog::info("Sent Noise identity announce");
    }
    catch (const std::exception &e)
    {
        spdlog::error("Failed to send Noise identity announce: {}", e.what());
    }
}

} // namespace bitchat
