#include "bitchat/noise/noise_session.h"
#include <algorithm>
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

namespace bitchat
{
namespace noise
{

// NoiseSession Implementation

class NoiseSessionImpl : public NoiseSession
{
private:
    std::string peerID;
    NoiseRole role;
    bool sessionEstablished;
    PrivateKey localStaticKey;
    std::optional<PublicKey> remoteStaticKey;
    std::optional<std::vector<uint8_t>> handshakeHash;

    // noise-c state
    NoiseHandshakeState *handshakeState;
    NoiseCipherState *sendCipher;
    NoiseCipherState *receiveCipher;

    // Security tracking
    uint64_t messageCount;
    std::chrono::system_clock::time_point sessionStartTime;
    std::chrono::system_clock::time_point lastActivityTime;

    // Handshake tracking
    uint32_t handshakeStep;

    // Thread safety
    mutable std::mutex sessionMutex;

public:
    NoiseSessionImpl(const std::string &peerID, NoiseRole role, const PrivateKey &localStaticKey)
        : peerID(peerID)
        , role(role)
        , sessionEstablished(false)
        , localStaticKey(localStaticKey)
        , handshakeState(nullptr)
        , sendCipher(nullptr)
        , receiveCipher(nullptr)
        , messageCount(0)
        , sessionStartTime(std::chrono::system_clock::now())
        , lastActivityTime(std::chrono::system_clock::now())
        , handshakeStep(0)
    {
    }

    ~NoiseSessionImpl()
    {
        if (handshakeState)
        {
            noise_handshakestate_free(handshakeState);
        }
        if (sendCipher)
        {
            noise_cipherstate_free(sendCipher);
        }
        if (receiveCipher)
        {
            noise_cipherstate_free(receiveCipher);
        }
    }

    std::string getPeerID() const override
    {
        return peerID;
    }

    bool isSessionEstablished() const override
    {
        std::lock_guard<std::mutex> lock(sessionMutex);
        return sessionEstablished;
    }

    std::optional<PublicKey> getRemoteStaticPublicKey() const override
    {
        std::lock_guard<std::mutex> lock(sessionMutex);
        return remoteStaticKey;
    }

    std::optional<std::vector<uint8_t>> getHandshakeHash() const override
    {
        std::lock_guard<std::mutex> lock(sessionMutex);
        return handshakeHash;
    }

    bool needsRenegotiation() const override
    {
        std::lock_guard<std::mutex> lock(sessionMutex);

        // Check if we've used more than 90% of message limit
        uint64_t messageThreshold = static_cast<uint64_t>(NoiseSecurityConstants::maxMessagesPerSession * 0.9);
        if (messageCount >= messageThreshold)
        {
            return true;
        }

        // Check if last activity was more than 30 minutes ago
        auto now = std::chrono::system_clock::now();
        if (now - lastActivityTime > std::chrono::minutes(30))
        {
            return true;
        }

        return false;
    }

    uint64_t getMessageCount() const override
    {
        std::lock_guard<std::mutex> lock(sessionMutex);
        return messageCount;
    }

    std::chrono::system_clock::time_point getLastActivityTime() const override
    {
        std::lock_guard<std::mutex> lock(sessionMutex);
        return lastActivityTime;
    }

    bool handshakeInProgress() const override
    {
        std::lock_guard<std::mutex> lock(sessionMutex);
        return !sessionEstablished && handshakeState != nullptr;
    }

    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext) override
    {
        std::lock_guard<std::mutex> lock(sessionMutex);

        if (!sessionEstablished || !sendCipher)
        {
            throw std::runtime_error("Session not established");
        }

        // Check session age
        auto now = std::chrono::system_clock::now();
        if (now - sessionStartTime > NoiseSecurityConstants::sessionTimeout)
        {
            throw std::runtime_error("Session expired");
        }

        // Check message count
        if (messageCount >= NoiseSecurityConstants::maxMessagesPerSession)
        {
            throw std::runtime_error("Session exhausted");
        }

        // Validate message size
        if (plaintext.size() > NoiseSecurityConstants::maxMessageSize)
        {
            throw std::runtime_error("Message too large");
        }

        // Use noise-c to encrypt
        std::vector<uint8_t> ciphertext(plaintext.size() + 16); // +16 for tag
        NoiseBuffer buffer;
        noise_buffer_set_inout(buffer, ciphertext.data(), plaintext.size(), ciphertext.size());

        // Copy plaintext to buffer
        std::copy(plaintext.begin(), plaintext.end(), ciphertext.begin());

        int result = noise_cipherstate_encrypt(sendCipher, &buffer);
        if (result != NOISE_ERROR_NONE)
        {
            throw std::runtime_error("Encryption failed");
        }

        ciphertext.resize(buffer.size);
        messageCount++;
        lastActivityTime = now;

        return ciphertext;
    }

    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext) override
    {
        std::lock_guard<std::mutex> lock(sessionMutex);

        if (!sessionEstablished || !receiveCipher)
        {
            throw std::runtime_error("Session not established");
        }

        // Check session age
        auto now = std::chrono::system_clock::now();
        if (now - sessionStartTime > NoiseSecurityConstants::sessionTimeout)
        {
            throw std::runtime_error("Session expired");
        }

        // Validate message size
        if (ciphertext.size() > NoiseSecurityConstants::maxMessageSize)
        {
            throw std::runtime_error("Message too large");
        }

        // Use noise-c to decrypt
        std::vector<uint8_t> plaintext(ciphertext.size());
        NoiseBuffer buffer;
        noise_buffer_set_inout(buffer, plaintext.data(), ciphertext.size(), ciphertext.size());

        // Copy ciphertext to buffer
        std::copy(ciphertext.begin(), ciphertext.end(), plaintext.begin());

        int result = noise_cipherstate_decrypt(receiveCipher, &buffer);
        if (result != NOISE_ERROR_NONE)
        {
            throw std::runtime_error("Decryption failed");
        }

        plaintext.resize(buffer.size);
        lastActivityTime = now;

        return plaintext;
    }

    // Helper function to log cipher state
    void logCipherState(const char *context, NoiseCipherState *cipher)
    {
        if (!cipher)
        {
            spdlog::info("{}: Cipher state is null", context);
            return;
        }

        // Note: noise-c doesn't expose key/nonce directly, so we log what we can
        spdlog::info("{}: Cipher state exists", context);

        // We can only log the cipher state pointer for now
        spdlog::info("{}: Cipher state pointer: {}", context, (void *)cipher);
    }

    // Internal methods for handshake
    std::vector<uint8_t> startHandshake()
    {
        std::lock_guard<std::mutex> lock(sessionMutex);

        spdlog::info("=== STARTING NOISE HANDSHAKE ===");
        spdlog::info("Peer: {}, Role: {}", peerID, role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");

        if (sessionEstablished)
        {
            spdlog::error("Session already established");
            throw std::runtime_error("Session already established");
        }

        // Validate local static key
        if (localStaticKey.size() != 32)
        {
            spdlog::error("Invalid local static key size: {} (expected 32)", localStaticKey.size());
            throw std::runtime_error("Invalid local static key size");
        }

        // Debug: log complete key for comparison with Swift
        std::string keyHex;
        for (size_t i = 0; i < localStaticKey.size(); ++i)
        {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", localStaticKey[i]);
            keyHex += hex;
        }
        spdlog::info("=== LOCAL STATIC KEY COMPARISON ===");
        spdlog::info("Local static key (32 bytes): {}", keyHex);
        spdlog::info("Expected from Swift: [COMPARE WITH SWIFT LOG]");
        spdlog::info("=== END KEY COMPARISON ===");

        // Initialize noise-c handshake state
        spdlog::info("Creating handshake state with pattern: Noise_XX_25519_ChaChaPoly_SHA256");
        spdlog::info("Role: {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
        spdlog::info("Expected protocol name from Swift: Noise_XX_25519_ChaChaPoly_SHA256");
        spdlog::info("Expected initial hash from Swift: 4e6f6973655f58585f32353531395f43...");

        int result = noise_handshakestate_new_by_name(&handshakeState, "Noise_XX_25519_ChaChaPoly_SHA256",
                                                      role == NoiseRole::Initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER);
        if (result != NOISE_ERROR_NONE)
        {
            char errorBuf[256];
            noise_strerror(result, errorBuf, sizeof(errorBuf));
            spdlog::error("Failed to create handshake state: {} ({})", result, errorBuf);
            throw std::runtime_error("Failed to create handshake state");
        }

        spdlog::info("Handshake state created successfully");
        spdlog::info("Handshake state pointer: {}", (void *)handshakeState);

        // Verify handshake state is valid
        if (!handshakeState)
        {
            spdlog::error("Handshake state is null after creation!");
            throw std::runtime_error("Handshake state is null after creation");
        }

        // Log initial hash state
        spdlog::info("=== CHECKING INITIAL HASH STATE ===");
        size_t initialHashLen = 32;
        std::vector<uint8_t> initialHash(initialHashLen);
        int initialHashResult = noise_handshakestate_get_handshake_hash(handshakeState, initialHash.data(), initialHashLen);
        spdlog::info("noise_handshakestate_get_handshake_hash returned: {} (0x{:x})", initialHashResult, initialHashResult);

        if (initialHashResult == NOISE_ERROR_NONE)
        {
            std::string initialHashHex;
            for (size_t i = 0; i < initialHash.size(); ++i)
            {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x", initialHash[i]);
                initialHashHex += tmp;
            }
            spdlog::info("=== INITIAL HASH COMPARISON ===");
            spdlog::info("Initial hash from noise-c: {}", initialHashHex);
            spdlog::info("Expected from Swift: 4e6f6973655f58585f32353531395f43...");
            spdlog::info("Protocol: Noise_XX_25519_ChaChaPoly_SHA256");
            spdlog::info("Role: {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
            spdlog::info("PeerID: {}", peerID);

            // Check if initial hash matches Swift
            std::string expectedInitialHash = "4e6f6973655f58585f32353531395f43";
            if (initialHashHex.substr(0, 32) == expectedInitialHash)
            {
                spdlog::info("✓ Initial hash matches Swift - protocol initialization is correct!");
            }
            else
            {
                spdlog::error("✗ Initial hash MISMATCH with Swift!");
                spdlog::error("Expected: {}", expectedInitialHash);
                spdlog::error("Got:      {}", initialHashHex.substr(0, 32));
                spdlog::error("This indicates a protocol name or initialization problem!");
            }
            spdlog::info("=== END INITIAL HASH COMPARISON ===");
        }
        else
        {
            char errorBuf[256];
            noise_strerror(initialHashResult, errorBuf, sizeof(errorBuf));
            spdlog::error("Failed to get initial hash: {} ({})", initialHashResult, errorBuf);
            spdlog::error("This is the root cause of the MAC failure!");
        }
        spdlog::info("=== END INITIAL HASH CHECK ===");

        // Set local static key
        spdlog::info("Setting local static key...");
        NoiseDHState *localDH = noise_handshakestate_get_local_keypair_dh(handshakeState);
        if (localDH)
        {
            spdlog::info("Local DH state found, setting private key...");
            result = noise_dhstate_set_keypair_private(localDH, localStaticKey.data(), localStaticKey.size());
            spdlog::info("noise_dhstate_set_keypair_private returned: {} (0x{:x})", result, result);

            if (result != NOISE_ERROR_NONE)
            {
                char errorBuf[256];
                noise_strerror(result, errorBuf, sizeof(errorBuf));
                spdlog::error("Failed to set local static key: {} ({})", result, errorBuf);
                throw std::runtime_error("Failed to set local static key");
            }
            spdlog::info("Local static key set successfully");

            // Verify the key was set correctly
            size_t keyLen = noise_dhstate_get_private_key_length(localDH);
            spdlog::info("Private key length in DH state: {}", keyLen);

            if (keyLen != localStaticKey.size())
            {
                spdlog::error("Key length mismatch: expected {}, got {}", localStaticKey.size(), keyLen);
                throw std::runtime_error("Key length mismatch");
            }
        }
        else
        {
            spdlog::error("No local DH state available");
            throw std::runtime_error("No local DH state available");
        }

        // Check if we need to start the handshake
        int action = noise_handshakestate_get_action(handshakeState);
        spdlog::info("Initial handshake action: {} (0x{:x})", action, action);

        // Start the handshake if needed
        if (action == NOISE_ACTION_NONE)
        {
            spdlog::info("Starting handshake...");
            result = noise_handshakestate_start(handshakeState);
            if (result != NOISE_ERROR_NONE)
            {
                char errorBuf[256];
                noise_strerror(result, errorBuf, sizeof(errorBuf));
                spdlog::error("Failed to start handshake: {} ({})", result, errorBuf);
                throw std::runtime_error("Failed to start handshake");
            }
            spdlog::info("Handshake started successfully");

            // Check action after start
            action = noise_handshakestate_get_action(handshakeState);
            spdlog::info("Handshake action after start: {} (0x{:x})", action, action);
        }

        // Only initiator writes the first message
        if (role == NoiseRole::Initiator)
        {
            spdlog::info("Initiator: preparing to write first message");

            // Double-check the action before writing
            action = noise_handshakestate_get_action(handshakeState);
            spdlog::info("Initiator handshake action before write: {} (0x{:x})", action, action);
            spdlog::info("Expected action: {} (0x{:x})", NOISE_ACTION_WRITE_MESSAGE, NOISE_ACTION_WRITE_MESSAGE);

            if (action == NOISE_ACTION_WRITE_MESSAGE)
            {
                spdlog::info("Initiator: calling writeHandshakeMessage()");
                return writeHandshakeMessage();
            }
            else
            {
                spdlog::error("Initiator handshake not ready for write, action: {} (0x{:x})", action, action);
                throw std::runtime_error("Handshake not ready for write");
            }
        }
        else
        {
            spdlog::info("Responder: waiting for first message");
        }

        spdlog::info("=== HANDSHAKE START COMPLETE ===");
        return std::vector<uint8_t>();
    }

    std::optional<std::vector<uint8_t>> processHandshakeMessage(const std::vector<uint8_t> &message) override
    {
        std::lock_guard<std::mutex> lock(sessionMutex);

        spdlog::info("=== PROCESSING HANDSHAKE MESSAGE ===");
        spdlog::info("Peer: {}, Message size: {}", peerID, message.size());
        spdlog::info("Role: {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
        spdlog::info("Protocol: Noise_XX_25519_ChaChaPoly_SHA256");

        // Log complete message for comparison
        std::string messageHex;
        for (size_t i = 0; i < message.size(); ++i)
        {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", message[i]);
            messageHex += hex;
        }
        spdlog::info("=== INCOMING MESSAGE COMPARISON ===");
        spdlog::info("Message hex: {}", messageHex);
        spdlog::info("Message size: {} bytes", message.size());
        spdlog::info("Expected from Swift: [COMPARE WITH SWIFT LOG]");
        spdlog::info("=== END MESSAGE COMPARISON ===");

        if (sessionEstablished)
        {
            spdlog::error("Session already established");
            throw std::runtime_error("Session already established");
        }

        // Validate message size based on role and handshake step
        // Noise XX pattern:
        // Initiator -> Responder: 32 bytes (ephemeral e)
        // Responder -> Initiator: 96 bytes (ephemeral e, static s, payload+tag)
        // Initiator -> Responder: 48 bytes (static s, payload)

        if (role == NoiseRole::Responder)
        {
            if (message.size() == 32)
            {
                spdlog::info("Responder: processing handshake init (32 bytes)");
                spdlog::info("Responder: after this, should generate 96-byte response");
            }
            else if (message.size() == 64)
            {
                spdlog::info("Responder: processing handshake final (64 bytes)");
                spdlog::info("Responder: this should complete the handshake!");
            }
            else if (message.size() == 96)
            {
                spdlog::warn("Responder received 96 bytes - should never happen, we are responder");
                return std::nullopt;
            }
            else
            {
                spdlog::error("Responder: unexpected message size: {} (expected 32 or 64)", message.size());
                throw std::runtime_error("Unexpected message size for responder");
            }
        }
        else // Initiator
        {
            if (message.size() == 96)
            {
                spdlog::info("Initiator: processing handshake response (96 bytes)");
                spdlog::info("Initiator: after this, should generate 64-byte final message");
            }
            else if (message.size() == 32)
            {
                spdlog::warn("Initiator received handshake init (32 bytes) - ignoring (should not happen)");
                return std::nullopt;
            }
            else if (message.size() == 64)
            {
                spdlog::warn("Initiator received 64 bytes - should never happen, we are initiator");
                return std::nullopt;
            }
            else
            {
                spdlog::error("Initiator: unexpected message size: {} (expected 96)", message.size());
                throw std::runtime_error("Unexpected message size for initiator");
            }
        }

        // Initialize handshake state if needed (for responders)
        if (!handshakeState)
        {
            spdlog::info("=== CREATING NEW HANDSHAKE STATE ===");
            spdlog::info("Role: {} (determined by message context)", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
            spdlog::info("Protocol: Noise_XX_25519_ChaChaPoly_SHA256");
            spdlog::info("Noise role: {}", role == NoiseRole::Initiator ? "NOISE_ROLE_INITIATOR" : "NOISE_ROLE_RESPONDER");

            int result = noise_handshakestate_new_by_name(&handshakeState, "Noise_XX_25519_ChaChaPoly_SHA256",
                                                          role == NoiseRole::Initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER);
            if (result != NOISE_ERROR_NONE)
            {
                char errorBuf[256];
                noise_strerror(result, errorBuf, sizeof(errorBuf));
                spdlog::error("Failed to create handshake state: {} ({})", result, errorBuf);
                throw std::runtime_error("Failed to create handshake state");
            }

            spdlog::info("Handshake state created for {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");

            NoiseDHState *localDH = noise_handshakestate_get_local_keypair_dh(handshakeState);
            if (localDH)
            {
                spdlog::info("Setting local static key for {}...", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
                spdlog::info("Local static key size: {} bytes", localStaticKey.size());

                // Log complete key for comparison
                std::string keyHex;
                for (size_t i = 0; i < localStaticKey.size(); ++i)
                {
                    char hex[3];
                    snprintf(hex, sizeof(hex), "%02x", localStaticKey[i]);
                    keyHex += hex;
                }
                spdlog::info("=== LOCAL STATIC KEY COMPARISON (PROCESS) ===");
                spdlog::info("Local static key (32 bytes): {}", keyHex);
                spdlog::info("Expected from Swift: [COMPARE WITH SWIFT LOG]");
                spdlog::info("=== END KEY COMPARISON ===");

                result = noise_dhstate_set_keypair_private(localDH, localStaticKey.data(), localStaticKey.size());
                if (result != NOISE_ERROR_NONE)
                {
                    char errorBuf[256];
                    noise_strerror(result, errorBuf, sizeof(errorBuf));
                    spdlog::error("Failed to set local static key: {} ({})", result, errorBuf);
                    throw std::runtime_error("Failed to set local static key");
                }
                spdlog::info("Local static key set successfully for {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");

                // Verify the key was set correctly
                size_t keyLen = noise_dhstate_get_private_key_length(localDH);
                spdlog::info("Private key length in DH state: {} bytes", keyLen);
            }
            else
            {
                spdlog::error("No local DH state available for {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
                throw std::runtime_error("No local DH state available");
            }

            // Start the handshake
            int action = noise_handshakestate_get_action(handshakeState);
            spdlog::info("{} handshake action before start: {} (0x{:x})",
                         role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER", action, action);

            if (action == NOISE_ACTION_NONE)
            {
                spdlog::info("Starting {} handshake...", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
                result = noise_handshakestate_start(handshakeState);
                if (result != NOISE_ERROR_NONE)
                {
                    char errorBuf[256];
                    noise_strerror(result, errorBuf, sizeof(errorBuf));
                    spdlog::error("Failed to start {} handshake: {} ({})",
                                  role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER", result, errorBuf);
                    throw std::runtime_error("Failed to start handshake");
                }
                spdlog::info("{} handshake started successfully", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");

                action = noise_handshakestate_get_action(handshakeState);
                spdlog::info("{} handshake action after start: {} (0x{:x})",
                             role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER", action, action);
            }
            else
            {
                spdlog::info("{} handshake already started, action: {} (0x{:x})",
                             role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER", action, action);
            }
        }
        else
        {
            spdlog::info("Using existing handshake state");
            int action = noise_handshakestate_get_action(handshakeState);
            spdlog::info("Current handshake action: {} (0x{:x})", action, action);
        }

        // Read the incoming message
        spdlog::info("Reading handshake message, size: {}", message.size());

        // Validate message data before processing
        spdlog::info("Trying to read handshake message: data={}, size={}", (void *)message.data(), message.size());

        if (!message.data() || message.size() == 0)
        {
            spdlog::error("Invalid message: data={}, size={}", (void *)message.data(), message.size());
            throw std::runtime_error("Invalid message data");
        }

        // Log complete message in hex for debugging
        std::string hex;
        for (auto b : message)
        {
            char tmp[4];
            snprintf(tmp, sizeof(tmp), "%02x", b);
            hex += tmp;
        }
        spdlog::info("Handshake input hex: {}", hex);

        // Log message structure for XX pattern
        if (message.size() == 96)
        {
            spdlog::info("=== XX PATTERN MESSAGE STRUCTURE ===");
            spdlog::info("Message size: 96 bytes (expected for XX responder->initiator)");

            // First 32 bytes: ephemeral key (e)
            std::string ephemeralHex;
            for (size_t i = 0; i < 32; ++i)
            {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x", message[i]);
                ephemeralHex += tmp;
            }
            spdlog::info("Ephemeral key (e) - 32 bytes: {}", ephemeralHex);

            // Next 48 bytes: encrypted static key (s)
            std::string staticHex;
            for (size_t i = 32; i < 80; ++i)
            {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x", message[i]);
                staticHex += tmp;
            }
            spdlog::info("Encrypted static key (s) - 48 bytes: {}", staticHex);

            // Last 16 bytes: payload tag
            std::string payloadHex;
            for (size_t i = 80; i < 96; ++i)
            {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x", message[i]);
                payloadHex += tmp;
            }
            spdlog::info("Payload tag - 16 bytes: {}", payloadHex);
            spdlog::info("=== END MESSAGE STRUCTURE ===");
        }

        // Log symmetric state before reading (if available)
        if (handshakeState)
        {
            // Get current hash state
            size_t hashLen = 32;
            std::vector<uint8_t> currentHash(hashLen);
            int hashResult = noise_handshakestate_get_handshake_hash(handshakeState, currentHash.data(), hashLen);
            if (hashResult == NOISE_ERROR_NONE)
            {
                std::string hashHex;
                for (size_t i = 0; i < currentHash.size(); ++i)
                {
                    char tmp[4];
                    snprintf(tmp, sizeof(tmp), "%02x", currentHash[i]);
                    hashHex += tmp;
                }
                spdlog::info("=== HASH STATE BEFORE READ ===");
                spdlog::info("Hash before read: {}", hashHex);
                spdlog::info("Expected from Swift: [COMPARE WITH SWIFT LOG]");
                spdlog::info("=== END HASH STATE ===");
            }
        }

        NoiseBuffer messageBuffer;
        noise_buffer_set_input(messageBuffer, const_cast<uint8_t *>(message.data()), message.size());
        spdlog::info("NoiseBuffer for read: data={}, size={}, max_size={}",
                     (void *)messageBuffer.data, messageBuffer.size, messageBuffer.max_size);

        // Create a valid payload buffer for output (required by noise-c)
        std::vector<uint8_t> payloadData(256); // Buffer to receive possible payload data
        NoiseBuffer payloadBuffer;
        noise_buffer_set_output(payloadBuffer, payloadData.data(), payloadData.size());
        spdlog::info("=== BUFFER CONFIGURATION ===");
        spdlog::info("Message buffer: data={}, size={}, max_size={}",
                     (void *)messageBuffer.data, messageBuffer.size, messageBuffer.max_size);
        spdlog::info("Payload buffer: data={}, size={}, max_size={}",
                     (void *)payloadBuffer.data, payloadBuffer.size, payloadBuffer.max_size);
        spdlog::info("Payload data vector size: {}", payloadData.size());
        spdlog::info("=== END BUFFER CONFIGURATION ===");

        // Validate buffers before calling read_message
        if (!messageBuffer.data || messageBuffer.size == 0 || messageBuffer.max_size == 0)
        {
            spdlog::error("Invalid messageBuffer for read: data={}, size={}, max_size={}",
                          (void *)messageBuffer.data, messageBuffer.size, messageBuffer.max_size);
            throw std::runtime_error("Invalid messageBuffer for read");
        }

        // Check if handshake state is ready for reading
        int currentAction = noise_handshakestate_get_action(handshakeState);
        spdlog::info("Handshake action before read: {} (0x{:x})", currentAction, currentAction);
        spdlog::info("Expected action for read: {} (0x{:x})", NOISE_ACTION_READ_MESSAGE, NOISE_ACTION_READ_MESSAGE);

        if (currentAction != NOISE_ACTION_READ_MESSAGE)
        {
            spdlog::error("Invalid handshake state for reading: {} (0x{:x}) (expected {} (0x{:x}))",
                          currentAction, currentAction, NOISE_ACTION_READ_MESSAGE, NOISE_ACTION_READ_MESSAGE);
            throw std::runtime_error("Invalid handshake state for reading");
        }

        spdlog::info("Calling noise_handshakestate_read_message...");
        spdlog::info("Handshake state: {}", (void *)handshakeState);
        spdlog::info("Message buffer: data={}, size={}, max_size={}",
                     (void *)messageBuffer.data, messageBuffer.size, messageBuffer.max_size);
        spdlog::info("Payload buffer: data={}, size={}, max_size={}",
                     (void *)payloadBuffer.data, payloadBuffer.size, payloadBuffer.max_size);

        // Log state before attempting to read message (this is where static key decryption happens)
        spdlog::info("=== BEFORE STATIC KEY DECRYPTION ===");

        // Get current hash state before decryption
        if (handshakeState)
        {
            size_t hashLen = 32;
            std::vector<uint8_t> currentHash(hashLen);
            int hashResult = noise_handshakestate_get_handshake_hash(handshakeState, currentHash.data(), hashLen);
            spdlog::info("noise_handshakestate_get_handshake_hash (before decryption) returned: {} (0x{:x})", hashResult, hashResult);

            if (hashResult == NOISE_ERROR_NONE)
            {
                std::string fullHashHex;
                for (size_t i = 0; i < currentHash.size(); ++i)
                {
                    char tmp[4];
                    snprintf(tmp, sizeof(tmp), "%02x", currentHash[i]);
                    fullHashHex += tmp;
                }
                spdlog::info("Hash before static key decryption: {}", fullHashHex);
                spdlog::info("Expected hash from Swift: d33afce27760c95140ba224877ed8ce7...");

                // Check if hash matches Swift
                std::string expectedHash = "d33afce27760c95140ba224877ed8ce7";
                if (fullHashHex.substr(0, 32) == expectedHash)
                {
                    spdlog::info("✓ Hash matches Swift - this is correct!");
                }
                else
                {
                    spdlog::error("✗ Hash MISMATCH with Swift!");
                    spdlog::error("Expected: {}", expectedHash);
                    spdlog::error("Got:      {}", fullHashHex.substr(0, 32));
                }
            }
            else
            {
                char errorBuf[256];
                noise_strerror(hashResult, errorBuf, sizeof(errorBuf));
                spdlog::error("Failed to get hash before decryption: {} ({})", hashResult, errorBuf);
                spdlog::error("This explains the MAC failure!");
            }
        }

        // Log the exact data that will be decrypted (static key field)
        if (message.size() >= 80)
        {
            std::string staticKeyHex;
            for (size_t i = 32; i < 80; ++i)
            {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x", message[i]);
                staticKeyHex += tmp;
            }
            spdlog::info("=== STATIC KEY DATA COMPARISON ===");
            spdlog::info("Static key data to decrypt (48 bytes): {}", staticKeyHex);
            spdlog::info("Expected from Swift: b27a49c908e0deafbd1f1a4e57b8f46c33b3f11cec59c5b6e3c985aa228116a4");
            spdlog::info("Role: {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
            spdlog::info("Message size: {} bytes", message.size());

            // Check if static key data matches Swift
            std::string expectedStaticKey = "b27a49c908e0deafbd1f1a4e57b8f46c33b3f11cec59c5b6e3c985aa228116a4";
            if (staticKeyHex == expectedStaticKey)
            {
                spdlog::info("✓ Static key data matches Swift - this is correct!");
            }
            else
            {
                spdlog::error("✗ Static key data MISMATCH with Swift!");
                spdlog::error("Expected: {}", expectedStaticKey);
                spdlog::error("Got:      {}", staticKeyHex);
                spdlog::error("This indicates a handshake state divergence!");
            }
            spdlog::info("=== END STATIC KEY DATA COMPARISON ===");
        }

        spdlog::info("=== ATTEMPTING STATIC KEY DECRYPTION ===");

        int result = noise_handshakestate_read_message(handshakeState, &messageBuffer, &payloadBuffer);
        spdlog::info("noise_handshakestate_read_message returned: {} (0x{:x})", result, result);

        if (result != NOISE_ERROR_NONE)
        {
            char errorBuf[256];
            noise_strerror(result, errorBuf, sizeof(errorBuf));
            spdlog::error("Failed to read handshake message: {} ({})", result, errorBuf);
            spdlog::error("Error details: {}", errorBuf);

            // Log additional debug info on failure
            spdlog::error("=== STATIC KEY DECRYPTION FAILED ===");
            spdlog::error("This is likely a MAC failure due to hash/nonce/key mismatch");
            spdlog::error("Compare the hash above with the Swift logs");

            throw std::runtime_error("Failed to read handshake message");
        }

        spdlog::info("Handshake message read successfully");

        // Increment handshake step after successful read
        handshakeStep++;
        spdlog::info("Handshake step incremented to: {} (after reading message)", handshakeStep);

        // Log symmetric state after reading
        if (handshakeState)
        {
            size_t hashLen = 32;
            std::vector<uint8_t> currentHash(hashLen);
            int hashResult = noise_handshakestate_get_handshake_hash(handshakeState, currentHash.data(), hashLen);
            if (hashResult == NOISE_ERROR_NONE)
            {
                std::string hashHex;
                for (size_t i = 0; i < currentHash.size(); ++i)
                {
                    char tmp[4];
                    snprintf(tmp, sizeof(tmp), "%02x", currentHash[i]);
                    hashHex += tmp;
                }
                spdlog::info("=== HASH STATE AFTER READ ===");
                spdlog::info("Hash after read: {}", hashHex);
                spdlog::info("Expected from Swift: [COMPARE WITH SWIFT LOG]");
                spdlog::info("=== END HASH STATE ===");
            }
        }

        // Check if handshake is complete
        int readAction = noise_handshakestate_get_action(handshakeState);
        spdlog::info("Handshake action after read: {} (0x{:x})", readAction, readAction);

        if (readAction == NOISE_ACTION_SPLIT)
        {
            spdlog::info("=== HANDSHAKE COMPLETE ===");
            spdlog::info("Role: {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
            spdlog::info("Getting transport ciphers");

            // Handshake complete, get transport ciphers
            result = noise_handshakestate_split(handshakeState, &sendCipher, &receiveCipher);
            if (result != NOISE_ERROR_NONE)
            {
                throw std::runtime_error("Failed to split handshake");
            }

            // Get remote static key
            NoiseDHState *remoteDH = noise_handshakestate_get_remote_public_key_dh(handshakeState);
            if (remoteDH)
            {
                size_t remoteKeyLen = noise_dhstate_get_public_key_length(remoteDH);
                spdlog::info("Remote public key length: {} bytes", remoteKeyLen);

                std::vector<uint8_t> remoteKeyData(remoteKeyLen);
                result = noise_dhstate_get_public_key(remoteDH, remoteKeyData.data(), remoteKeyLen);
                if (result == NOISE_ERROR_NONE)
                {
                    remoteStaticKey.emplace();
                    std::copy(remoteKeyData.begin(), remoteKeyData.end(), remoteStaticKey->begin());

                    // Log first few bytes of remote public key
                    std::string remoteKeyHex;
                    for (size_t i = 0; i < std::min(size_t(16), remoteKeyData.size()); ++i)
                    {
                        char hex[3];
                        snprintf(hex, sizeof(hex), "%02x", remoteKeyData[i]);
                        remoteKeyHex += hex;
                    }
                    spdlog::info("Remote public key (first 16 bytes): {}", remoteKeyHex);
                }
                else
                {
                    spdlog::error("Failed to get remote public key: {}", result);
                }
            }
            else
            {
                spdlog::warn("No remote DH state available");
            }

            // Get handshake hash
            size_t hashLen = 32;
            handshakeHash.emplace(hashLen);
            result = noise_handshakestate_get_handshake_hash(handshakeState, handshakeHash->data(), hashLen);
            if (result != NOISE_ERROR_NONE)
            {
                spdlog::error("Failed to get handshake hash: {}", result);
                handshakeHash.reset();
            }
            else
            {
                // Log first few bytes of handshake hash for debugging
                std::string hashHex;
                for (size_t i = 0; i < std::min(size_t(16), handshakeHash->size()); ++i)
                {
                    char hex[3];
                    snprintf(hex, sizeof(hex), "%02x", (*handshakeHash)[i]);
                    hashHex += hex;
                }
                spdlog::info("Handshake hash (first 16 bytes): {}", hashHex);
            }

            sessionEstablished = true;
            spdlog::info("=== SESSION ESTABLISHED ===");
            spdlog::info("Role: {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
            spdlog::info("Peer: {}", peerID);
            spdlog::info("Session is now ready for encrypted communication");

            noise_handshakestate_free(handshakeState);
            handshakeState = nullptr;

            return std::nullopt;
        }
        else if (readAction == NOISE_ACTION_WRITE_MESSAGE)
        {
            spdlog::info("=== HANDSHAKE NEEDS RESPONSE ===");
            spdlog::info("Role: {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");

            if (role == NoiseRole::Responder)
            {
                spdlog::info("Responder: generating 96-byte response to initiator");
                spdlog::info("This should be the first response in the XX handshake");
            }
            else
            {
                spdlog::info("Initiator: generating 48-byte final message to responder");
                spdlog::info("This should be the FINAL message of the handshake");
                spdlog::info("After this, handshake should be complete");
            }

            // Generate response
            auto response = writeHandshakeMessage();
            spdlog::info("Generated response message, size: {} bytes", response.size());

            // CRITICAL FIX: For initiator, establish session after writing final message
            // Check if this is the final message (handshake step 2 for initiator)
            spdlog::info("=== CHECKING INITIATOR SESSION ESTABLISHMENT ===");
            spdlog::info("Role: {}", (role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER"));
            spdlog::info("Handshake step: {}", handshakeStep);

            // Get current handshake action from noise-c
            int handshakeAction = noise_handshakestate_get_action(handshakeState);
            spdlog::info("Handshake action after write: {} (0x{:x})", handshakeAction, handshakeAction);
            spdlog::info("Condition check: role == Initiator && handshakeAction == 16644 (complete)");
            spdlog::info("Result: {}", (role == NoiseRole::Initiator && handshakeAction == 16644));

            if (role == NoiseRole::Initiator && handshakeAction == 16644)
            {
                spdlog::info("=== INITIATOR SESSION ESTABLISHMENT ===");
                spdlog::info("Initiator completed handshake by sending final message");
                spdlog::info("Establishing session for initiator...");

                // CRITICAL FIX: Get transport ciphers for initiator
                spdlog::info("Getting transport ciphers for initiator");
                int result = noise_handshakestate_split(handshakeState, &sendCipher, &receiveCipher);
                if (result != NOISE_ERROR_NONE)
                {
                    spdlog::error("Failed to split handshake for initiator: {}", result);
                    throw std::runtime_error("Failed to split handshake for initiator");
                }

                // Get remote static key
                NoiseDHState *remoteDH = noise_handshakestate_get_remote_public_key_dh(handshakeState);
                if (remoteDH)
                {
                    size_t remoteKeyLen = noise_dhstate_get_public_key_length(remoteDH);
                    spdlog::info("Remote public key length: {} bytes", remoteKeyLen);

                    std::vector<uint8_t> remoteKeyData(remoteKeyLen);
                    result = noise_dhstate_get_public_key(remoteDH, remoteKeyData.data(), remoteKeyLen);
                    if (result == NOISE_ERROR_NONE)
                    {
                        remoteStaticKey.emplace();
                        std::copy(remoteKeyData.begin(), remoteKeyData.end(), remoteStaticKey->begin());

                        // Log first few bytes of remote public key
                        std::string remoteKeyHex;
                        for (size_t i = 0; i < std::min(size_t(16), remoteKeyData.size()); ++i)
                        {
                            char hex[3];
                            snprintf(hex, sizeof(hex), "%02x", remoteKeyData[i]);
                            remoteKeyHex += hex;
                        }
                        spdlog::info("Remote public key (first 16 bytes): {}", remoteKeyHex);
                    }
                    else
                    {
                        spdlog::error("Failed to get remote public key: {}", result);
                    }
                }
                else
                {
                    spdlog::warn("No remote DH state available");
                }

                // Get handshake hash
                size_t hashLen = 32;
                handshakeHash = std::vector<uint8_t>(hashLen);
                result = noise_handshakestate_get_handshake_hash(handshakeState, handshakeHash->data(), hashLen);
                if (result != NOISE_ERROR_NONE)
                {
                    spdlog::error("Failed to get handshake hash: {}", result);
                    handshakeHash.reset();
                }
                else
                {
                    std::string hashHex;
                    for (size_t i = 0; i < std::min(size_t(16), handshakeHash->size()); ++i)
                    {
                        char hex[3];
                        snprintf(hex, sizeof(hex), "%02x", (*handshakeHash)[i]);
                        hashHex += hex;
                    }
                    spdlog::info("Handshake hash (first 16 bytes): {}", hashHex);
                }

                sessionEstablished = true;
                spdlog::info("=== SESSION ESTABLISHED ===");
                spdlog::info("Role: INITIATOR");
                spdlog::info("Peer: {}", peerID);
                spdlog::info("Session is now ready for encrypted communication");

                noise_handshakestate_free(handshakeState);
                handshakeState = nullptr;
            }

            spdlog::info("Returning response for transmission");
            return response;
        }
        else
        {
            spdlog::warn("Unexpected handshake action after read: {} (0x{:x})", readAction, readAction);
            return std::nullopt;
        }
    }

private:
    std::vector<uint8_t> writeHandshakeMessage()
    {
        spdlog::info("=== WRITING HANDSHAKE MESSAGE ===");

        // Validate handshake state
        if (!handshakeState)
        {
            spdlog::error("Handshake state is null");
            throw std::runtime_error("Handshake state is null");
        }

        // Log symmetric state before writing
        size_t hashLen = 32;
        std::vector<uint8_t> currentHash(hashLen);
        int hashResult = noise_handshakestate_get_handshake_hash(handshakeState, currentHash.data(), hashLen);
        if (hashResult == NOISE_ERROR_NONE)
        {
            std::string hashHex;
            for (size_t i = 0; i < std::min(size_t(16), currentHash.size()); ++i)
            {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x", currentHash[i]);
                hashHex += tmp;
            }
            spdlog::info("Symmetric state hash before write (first 16 bytes): {}", hashHex);
        }

        // Check if we're in the right state to write
        int action = noise_handshakestate_get_action(handshakeState);
        spdlog::info("Current handshake action: {} (0x{:x})", action, action);
        spdlog::info("Expected action: {} (0x{:x})", NOISE_ACTION_WRITE_MESSAGE, NOISE_ACTION_WRITE_MESSAGE);

        if (action != NOISE_ACTION_WRITE_MESSAGE)
        {
            spdlog::error("Invalid handshake state for writing: {} (0x{:x}) (expected {} (0x{:x}))",
                          action, action, NOISE_ACTION_WRITE_MESSAGE, NOISE_ACTION_WRITE_MESSAGE);
            throw std::runtime_error("Invalid handshake state for writing");
        }

        // Debug handshake state before writing
        spdlog::info("=== HANDSHAKE STATE DEBUG ===");
        spdlog::info("Role: {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
        spdlog::info("Protocol: Noise_XX_25519_ChaChaPoly_SHA256");

        // Get current hash to understand handshake progress (reuse existing variables)
        hashResult = noise_handshakestate_get_handshake_hash(handshakeState, currentHash.data(), hashLen);
        if (hashResult == NOISE_ERROR_NONE)
        {
            std::string hashHex;
            for (size_t i = 0; i < std::min(size_t(16), currentHash.size()); ++i)
            {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x", currentHash[i]);
                hashHex += tmp;
            }
            spdlog::info("Hash before write (first 16 bytes): {}", hashHex);
        }

        // Check handshake step and expected message size
        spdlog::info("=== HANDSHAKE STEP ANALYSIS ===");
        spdlog::info("Current handshake step: {}", handshakeStep);

        if (role == NoiseRole::Initiator)
        {
            if (handshakeStep == 0)
            {
                spdlog::info("Initiator: This is the FIRST message (32 bytes)");
                spdlog::info("Initiator: Expected: 32 bytes (ephemeral key)");
            }
            else if (handshakeStep == 2)
            {
                spdlog::info("Initiator: This is the FINAL message (48 bytes)");
                spdlog::info("Initiator: Expected: 48 bytes (static key + payload)");
            }
            else
            {
                spdlog::error("Initiator: Unexpected handshake step: {}", handshakeStep);
                throw std::runtime_error("Unexpected handshake step for initiator");
            }
        }
        else if (role == NoiseRole::Responder)
        {
            if (handshakeStep == 1)
            {
                spdlog::info("Responder: This is the RESPONSE message (96 bytes)");
                spdlog::info("Responder: Expected: 96 bytes (ephemeral + encrypted static + tag)");
            }
            else
            {
                spdlog::error("Responder: Unexpected handshake step: {}", handshakeStep);
                throw std::runtime_error("Unexpected handshake step for responder");
            }
        }
        spdlog::info("=== END HANDSHAKE STEP ANALYSIS ===");

        spdlog::info("=== END HANDSHAKE STATE DEBUG ===");

        spdlog::info("Preparing message buffer (1024 bytes)");
        NoiseBuffer messageBuffer;

        // Buffer size - start with 1024 but will resize to actual size
        std::vector<uint8_t> message(1024);

        // Initialize the buffer properly for output - CRITICAL FIX!
        noise_buffer_init(messageBuffer);
        noise_buffer_set_output(messageBuffer, message.data(), message.size());
        messageBuffer.size = 0; // CRITICAL: Always 0 for output buffers before write!

        spdlog::info("Message buffer initialized: data={}, size={}, max_size={}",
                     (void *)messageBuffer.data, messageBuffer.size, messageBuffer.max_size);
        spdlog::info("✓ Correct: size=0, max_size=1024 (noise-c will set size after write)");

        spdlog::info("Preparing payload buffer (empty)");
        // CRITICAL FIX: For Noise XX handshake, we need to understand why noise-c is adding AEAD tag
        // The issue might be that noise-c is interpreting the handshake state incorrectly
        // Let's try with NO payload buffer at all to see if this is the issue
        spdlog::info("✓ No payload buffer provided (testing if nullptr causes AEAD tag)");

        // Validate all parameters before calling write_message
        spdlog::info("Validating parameters before write_message...");

        // Check handshake state
        if (!handshakeState)
        {
            spdlog::error("handshakeState is null");
            throw std::runtime_error("handshakeState is null");
        }

        // Check message buffer
        if (!messageBuffer.data || messageBuffer.max_size == 0)
        {
            spdlog::error("messageBuffer is invalid: data={}, size={}, max_size={}",
                          (void *)messageBuffer.data, messageBuffer.size, messageBuffer.max_size);
            throw std::runtime_error("messageBuffer is invalid");
        }

        // Verify buffer is properly initialized for output
        if (messageBuffer.size != 0)
        {
            spdlog::error("messageBuffer.size should be 0 before write, got: {}", messageBuffer.size);
            throw std::runtime_error("messageBuffer.size should be 0 before write");
        }

        // No payload buffer validation needed - we're not using one
        spdlog::info("✓ No payload buffer provided (testing if nullptr causes AEAD tag)");

        // CRITICAL FIX: Force set local static key before write_message
        spdlog::info("=== FORCE SET LOCAL STATIC KEY ===");
        NoiseDHState *localDH = noise_handshakestate_get_local_keypair_dh(handshakeState);
        if (!localDH)
        {
            spdlog::error("No local DH state available for write");
            throw std::runtime_error("No local DH state available");
        }

        spdlog::info("Setting local static key before write_message...");
        spdlog::info("Local static key size: {} bytes", localStaticKey.size());

        // Log first few bytes of the key being set
        std::string keyHex;
        for (size_t i = 0; i < std::min(size_t(8), localStaticKey.size()); ++i)
        {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", localStaticKey[i]);
            keyHex += hex;
        }
        spdlog::info("Local static key (first 8 bytes): {}", keyHex);

        int keyResult = noise_dhstate_set_keypair_private(localDH, localStaticKey.data(), localStaticKey.size());
        spdlog::info("noise_dhstate_set_keypair_private returned: {} (0x{:x})", keyResult, keyResult);

        if (keyResult != NOISE_ERROR_NONE)
        {
            char errorBuf[256];
            noise_strerror(keyResult, errorBuf, sizeof(errorBuf));
            spdlog::error("Failed to re-set local static key just before write: {} ({})", keyResult, errorBuf);
            throw std::runtime_error("Failed to set local static key before write");
        }
        spdlog::info("✓ Local static key set successfully before write_message");
        spdlog::info("=== END FORCE SET LOCAL STATIC KEY ===");

        spdlog::info("All parameters validated, calling noise_handshakestate_write_message...");
        spdlog::info("✓ Message buffer: size=0, max_size=1024 (correct for output)");
        spdlog::info("✓ No payload buffer (testing if nullptr causes AEAD tag)");
        // CRITICAL: Pass nullptr for payload buffer to test if this causes AEAD tag
        int result = noise_handshakestate_write_message(handshakeState, &messageBuffer, nullptr);
        spdlog::info("noise_handshakestate_write_message returned: {} (0x{:x})", result, result);

        if (result != NOISE_ERROR_NONE)
        {
            char errorBuf[256];
            noise_strerror(result, errorBuf, sizeof(errorBuf));
            spdlog::error("Failed to write handshake message: {} ({})", result, errorBuf);
            spdlog::error("Error details: {}", errorBuf);
            throw std::runtime_error("Failed to write handshake message");
        }

        // Log buffer state after write
        spdlog::info("=== BUFFER SIZE DEBUG ===");
        spdlog::info("After write_message: messageBuffer.size={}, messageBuffer.max_size={}",
                     messageBuffer.size, messageBuffer.max_size);
        spdlog::info("Role: {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");

        if (role == NoiseRole::Initiator)
        {
            if (handshakeStep == 0)
            {
                spdlog::info("Initiator expected: 32 bytes (first XX message)");
                if (messageBuffer.size != 32)
                {
                    spdlog::error("CRITICAL ERROR: Initiator generated {} bytes, expected 32 bytes!", messageBuffer.size);
                    spdlog::error("This will cause handshake failure - the responder expects exactly 32 bytes");

                    // Log the actual bytes being written for debugging
                    spdlog::info("=== ACTUAL BUFFER CONTENT DEBUG ===");
                    std::string bufferHex;
                    for (size_t i = 0; i < messageBuffer.size; ++i)
                    {
                        char hex[3];
                        snprintf(hex, sizeof(hex), "%02x", messageBuffer.data[i]);
                        bufferHex += hex;
                    }
                    spdlog::info("Buffer content ({} bytes): {}", messageBuffer.size, bufferHex);
                    spdlog::info("=== END BUFFER CONTENT DEBUG ===");
                }
            }
            else if (handshakeStep == 2)
            {
                spdlog::info("Initiator expected: 64 bytes (final XX message with 32-byte AEAD tag)");
                if (messageBuffer.size != 64)
                {
                    spdlog::error("CRITICAL ERROR: Initiator generated {} bytes, expected 64 bytes!", messageBuffer.size);
                    spdlog::error("This will cause handshake failure - the responder expects exactly 64 bytes");

                    // Log the actual bytes being written for debugging
                    spdlog::info("=== ACTUAL BUFFER CONTENT DEBUG ===");
                    std::string bufferHex;
                    for (size_t i = 0; i < messageBuffer.size; ++i)
                    {
                        char hex[3];
                        snprintf(hex, sizeof(hex), "%02x", messageBuffer.data[i]);
                        bufferHex += hex;
                    }
                    spdlog::info("Buffer content ({} bytes): {}", messageBuffer.size, bufferHex);
                    spdlog::info("=== END BUFFER CONTENT DEBUG ===");
                }
            }
        }
        else if (role == NoiseRole::Responder)
        {
            spdlog::info("Responder expected: 96 bytes (XX response message)");
            if (messageBuffer.size != 96)
            {
                spdlog::error("CRITICAL ERROR: Responder generated {} bytes, expected 96 bytes!", messageBuffer.size);
            }
        }

        if (messageBuffer.size == 0)
        {
            spdlog::error("ERROR: messageBuffer.size is 0 after write_message!");
            spdlog::error("This indicates a noise-c buffer initialization problem");
            throw std::runtime_error("Buffer size is 0 after write_message");
        }

        if (messageBuffer.size > messageBuffer.max_size)
        {
            spdlog::error("ERROR: messageBuffer.size ({}) > max_size ({})",
                          messageBuffer.size, messageBuffer.max_size);
            throw std::runtime_error("Buffer overflow detected");
        }

        spdlog::info("=== END BUFFER SIZE DEBUG ===");

        // CRITICAL: Only use the exact bytes written by noise-c
        spdlog::info("=== MESSAGE RESIZE DEBUG ===");
        spdlog::info("Before resize: message.size() = {}", message.size());
        spdlog::info("noise-c wrote: messageBuffer.size = {} bytes", messageBuffer.size);
        spdlog::info("noise-c buffer max: messageBuffer.max_size = {} bytes", messageBuffer.max_size);

        // Resize to ONLY the bytes actually written by noise-c
        message.resize(messageBuffer.size);
        spdlog::info("After resize: message.size() = {} bytes", message.size());

        // Verify we're not returning extra bytes
        if (message.size() != messageBuffer.size)
        {
            spdlog::error("CRITICAL ERROR: message.size() ({}) != messageBuffer.size ({})",
                          message.size(), messageBuffer.size);
            throw std::runtime_error("Message size mismatch after resize");
        }

        spdlog::info("✓ Message correctly resized to {} bytes", message.size());
        spdlog::info("=== END MESSAGE RESIZE DEBUG ===");

        // Validate message size based on role and handshake step
        bool sizeValid = false;
        if (role == NoiseRole::Initiator)
        {
            if (handshakeStep == 0)
            {
                // Initiator first message should be 32 bytes
                sizeValid = (message.size() == 32);
                if (!sizeValid)
                {
                    spdlog::warn("Initiator first message size mismatch: got {} bytes, expected 32 bytes", message.size());
                    spdlog::warn("This might indicate a noise-c configuration issue");
                }
            }
            else if (handshakeStep == 2)
            {
                // Initiator final message should be 48 bytes
                sizeValid = (message.size() == 48);
                if (!sizeValid)
                {
                    spdlog::warn("Initiator final message size mismatch: got {} bytes, expected 48 bytes", message.size());
                    spdlog::warn("This might indicate a noise-c configuration issue");
                }
            }
        }
        else if (role == NoiseRole::Responder)
        {
            if (handshakeStep == 1)
            {
                // Responder response should be 96 bytes
                sizeValid = (message.size() == 96);
                if (!sizeValid)
                {
                    spdlog::warn("Responder response message size mismatch: got {} bytes, expected 96 bytes", message.size());
                    spdlog::warn("This might indicate a noise-c configuration issue");
                }
            }
        }

        if (sizeValid)
        {
            spdlog::info("✓ Message size is correct for role");
        }
        else
        {
            spdlog::warn("⚠ Message size validation failed - continuing anyway");
        }

        // Log symmetric state after writing
        hashResult = noise_handshakestate_get_handshake_hash(handshakeState, currentHash.data(), hashLen);
        if (hashResult == NOISE_ERROR_NONE)
        {
            std::string hashHex;
            for (size_t i = 0; i < std::min(size_t(16), currentHash.size()); ++i)
            {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%02x", currentHash[i]);
                hashHex += tmp;
            }
            spdlog::info("Symmetric state hash after write (first 16 bytes): {}", hashHex);
        }

        if (role == NoiseRole::Responder)
        {
            spdlog::info("Responder: expected 96 bytes, got {} bytes", message.size());
            if (message.size() != 96)
            {
                spdlog::warn("Responder generated message of {} bytes, expected 96 bytes", message.size());
            }
        }
        else if (role == NoiseRole::Initiator)
        {
            spdlog::info("Initiator: expected 48 bytes, got {} bytes", message.size());
            if (message.size() != 48)
            {
                spdlog::warn("Initiator generated message of {} bytes, expected 48 bytes", message.size());
            }
        }

        // Log complete message for comparison
        std::string messageHex;
        for (size_t i = 0; i < message.size(); ++i)
        {
            char hex[3];
            snprintf(hex, sizeof(hex), "%02x", message[i]);
            messageHex += hex;
        }
        spdlog::info("=== OUTGOING MESSAGE COMPARISON ===");
        spdlog::info("Handshake message ({} bytes): {}", message.size(), messageHex);
        spdlog::info("Expected from Swift: [COMPARE WITH SWIFT LOG]");
        spdlog::info("Role: {}", role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER");
        spdlog::info("=== END MESSAGE COMPARISON ===");

        // Check if handshake is complete after writing
        int writeAction = noise_handshakestate_get_action(handshakeState);
        spdlog::info("Handshake action after write: {} (0x{:x})", writeAction, writeAction);

        if (writeAction == NOISE_ACTION_SPLIT)
        {
            spdlog::info("Handshake complete after write - should not send more messages");
        }

        spdlog::info("=== FINAL MESSAGE VERIFICATION ===");
        spdlog::info("Returning message with size: {} bytes", message.size());

        // Final verification based on handshake step
        if (role == NoiseRole::Initiator)
        {
            if (handshakeStep == 0 && message.size() != 32)
            {
                spdlog::error("FINAL VERIFICATION FAILED: Initiator first message returning {} bytes, expected 32 bytes", message.size());
                spdlog::error("This will cause handshake failure - the responder will reject this message");
                spdlog::error("The issue is that noise-c is writing {} bytes instead of 32", message.size());
            }
            else if (handshakeStep == 2 && message.size() != 64)
            {
                spdlog::error("FINAL VERIFICATION FAILED: Initiator final message returning {} bytes, expected 64 bytes", message.size());
                spdlog::error("This will cause handshake failure - the responder will reject this message");
                spdlog::error("The issue is that noise-c is writing {} bytes instead of 64", message.size());
            }

            // Log the first 48 bytes to see if there's extra data
            std::string first48Hex;
            for (size_t i = 0; i < std::min(size_t(48), message.size()); ++i)
            {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", message[i]);
                first48Hex += hex;
            }
            spdlog::info("First 48 bytes: {}", first48Hex);

            if (message.size() > 48)
            {
                std::string extraHex;
                for (size_t i = 48; i < message.size(); ++i)
                {
                    char hex[3];
                    snprintf(hex, sizeof(hex), "%02x", message[i]);
                    extraHex += hex;
                }
                spdlog::info("Extra bytes ({}): {}", message.size() - 48, extraHex);
            }
        }
        else if (role == NoiseRole::Responder && message.size() != 96)
        {
            spdlog::error("FINAL VERIFICATION FAILED: Responder returning {} bytes, expected 96 bytes", message.size());
        }
        else
        {
            spdlog::info("✓ Final verification passed: message size is correct");
        }

        spdlog::info("=== END FINAL MESSAGE VERIFICATION ===");

        // Increment handshake step
        handshakeStep++;
        spdlog::info("Handshake step incremented to: {}", handshakeStep);

        spdlog::info("=== HANDSHAKE MESSAGE WRITTEN ===");
        return message;
    }
};

// NoiseSessionManager Implementation

NoiseSessionManager::NoiseSessionManager(const PrivateKey &localStaticKey)
    : localStaticKey(localStaticKey)
{
    spdlog::info("=== NOISE SESSION MANAGER CONSTRUCTOR ===");
    spdlog::info("Local static key size: {}", localStaticKey.size());

    // Test noise-c functionality
    spdlog::info("Testing noise-c functionality...");

    // Check if noise-c is properly configured
    spdlog::info("NOISE_ACTION_WRITE_MESSAGE: {} (0x{:x})", NOISE_ACTION_WRITE_MESSAGE, NOISE_ACTION_WRITE_MESSAGE);
    spdlog::info("NOISE_ROLE_INITIATOR: {} (0x{:x})", NOISE_ROLE_INITIATOR, NOISE_ROLE_INITIATOR);
    spdlog::info("NOISE_ERROR_NONE: {} (0x{:x})", NOISE_ERROR_NONE, NOISE_ERROR_NONE);

    NoiseHandshakeState *testState = nullptr;
    int result = noise_handshakestate_new_by_name(&testState, "Noise_XX_25519_ChaChaPoly_SHA256", NOISE_ROLE_INITIATOR);
    spdlog::info("noise_handshakestate_new_by_name returned: {} (0x{:x})", result, result);

    if (result == NOISE_ERROR_NONE && testState)
    {
        spdlog::info("Noise-c test: handshake state creation successful");

        // Test getting action
        int testAction = noise_handshakestate_get_action(testState);
        spdlog::info("Test handshake action: {} (0x{:x})", testAction, testAction);

        // Test setting private key (required for XX pattern)
        NoiseDHState *testDH = noise_handshakestate_get_local_keypair_dh(testState);
        if (testDH)
        {
            // Create a test key (32 bytes of zeros for testing)
            std::vector<uint8_t> testKey(32, 0);
            int keyResult = noise_dhstate_set_keypair_private(testDH, testKey.data(), testKey.size());
            spdlog::info("Test key set result: {} (0x{:x})", keyResult, keyResult);
        }

        // Test starting handshake
        int startResult = noise_handshakestate_start(testState);
        spdlog::info("Test handshake start returned: {} (0x{:x})", startResult, startResult);

        if (startResult == NOISE_ERROR_NONE)
        {
            testAction = noise_handshakestate_get_action(testState);
            spdlog::info("Test handshake action after start: {} (0x{:x})", testAction, testAction);
            spdlog::info("Noise-c test completed successfully");
        }
        else
        {
            char errorBuf[256];
            noise_strerror(startResult, errorBuf, sizeof(errorBuf));
            spdlog::error("Test handshake start failed: {} ({})", startResult, errorBuf);
            spdlog::error("Noise-c test FAILED - this indicates a configuration problem");
        }

        noise_handshakestate_free(testState);
    }
    else
    {
        char errorBuf[256];
        noise_strerror(result, errorBuf, sizeof(errorBuf));
        spdlog::error("Noise-c test: handshake state creation failed: {} ({})", result, errorBuf);
        spdlog::error("Error details: {}", errorBuf);
    }

    spdlog::info("=== NOISE SESSION MANAGER CONSTRUCTOR COMPLETE ===");
}

std::shared_ptr<NoiseSession> NoiseSessionManager::createSession(const std::string &peerID, NoiseRole role)
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    auto session = std::make_shared<NoiseSessionImpl>(peerID, role, localStaticKey);
    sessions[peerID] = session;
    return session;
}

std::shared_ptr<NoiseSession> NoiseSessionManager::getSession(const std::string &peerID) const
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    auto it = sessions.find(peerID);
    if (it != sessions.end())
    {
        return it->second;
    }
    return nullptr;
}

void NoiseSessionManager::removeSession(const std::string &peerID)
{
    std::lock_guard<std::mutex> lock(sessionsMutex);
    sessions.erase(peerID);
}

std::unordered_map<std::string, std::shared_ptr<NoiseSession>> NoiseSessionManager::getEstablishedSessions() const
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    std::unordered_map<std::string, std::shared_ptr<NoiseSession>> established;
    for (const auto &[peerID, session] : sessions)
    {
        if (session->isSessionEstablished())
        {
            established[peerID] = session;
        }
    }
    return established;
}

std::vector<uint8_t> NoiseSessionManager::initiateHandshake(const std::string &remotePeerID)
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    spdlog::info("=== INITIATING HANDSHAKE ===");
    spdlog::info("Remote Peer ID: {}", remotePeerID);

    // Check if we already have an established session
    auto it = sessions.find(remotePeerID);
    if (it != sessions.end() && it->second->isSessionEstablished())
    {
        spdlog::warn("Session already established with {}", remotePeerID);
        throw std::runtime_error("Session already established");
    }

    // Remove any existing session (we're starting fresh)
    if (it != sessions.end())
    {
        spdlog::info("Removing existing session for {}", remotePeerID);
        sessions.erase(it);
    }

    // Create new session with Initiator role (we're initiating)
    spdlog::info("Creating new initiator session for {}", remotePeerID);
    auto session = std::make_shared<NoiseSessionImpl>(remotePeerID, NoiseRole::Initiator, localStaticKey);
    sessions[remotePeerID] = session;

    try
    {
        spdlog::info("Calling session->startHandshake()...");
        auto handshakeData = session->startHandshake();
        spdlog::info("Handshake initiated successfully with {}, data size: {}", remotePeerID, handshakeData.size());
        spdlog::info("=== HANDSHAKE INITIATION COMPLETE ===");
        return handshakeData;
    }
    catch (const std::exception &e)
    {
        // Clean up failed session
        spdlog::error("Handshake initiation failed for {}: {}", remotePeerID, e.what());
        sessions.erase(remotePeerID);
        throw;
    }
}

std::optional<std::vector<uint8_t>> NoiseSessionManager::handleIncomingHandshake(
    const std::string &remotePeerID,
    const std::vector<uint8_t> &message,
    const std::string &localPeerID)
{
    std::lock_guard<std::mutex> lock(sessionsMutex);
    spdlog::info("HandleIncomingHandshake: local='{}', remote='{}'", localPeerID, remotePeerID);

    // Always define role by PeerID, never by message size
    const NoiseRole role = resolveRole(localPeerID, remotePeerID);
    spdlog::info("=== ROLE RESOLUTION COMPARISON ===");
    spdlog::info("Local PeerID: '{}'", localPeerID);
    spdlog::info("Remote PeerID: '{}'", remotePeerID);
    spdlog::info("Role comparison: '{}' < '{}' = {}", localPeerID, remotePeerID, localPeerID < remotePeerID);
    spdlog::info("Resolved role: {}", (role == NoiseRole::Initiator ? "INITIATOR" : "RESPONDER"));
    spdlog::info("Expected from Swift: [COMPARE WITH SWIFT LOG]");
    spdlog::info("=== END ROLE RESOLUTION ===");

    // If receiving an INIT handshake (32 bytes), ALWAYS reset the session
    bool forceReset = (message.size() == 32);
    spdlog::info("Message size: {} bytes, forceReset: {}", message.size(), forceReset);

    auto it = sessions.find(remotePeerID);
    if (it != sessions.end())
    {
        auto session = it->second;

        // Any INIT: always reset!
        if (forceReset)
        {
            spdlog::info("Forcing session reset on new handshake INIT from {}", remotePeerID);
            sessions.erase(it);
        }
        else if (session->isSessionEstablished())
        {
            if (session->needsRenegotiation())
            {
                spdlog::info("Established session needs rekey for {}", remotePeerID);
                sessions.erase(it);
            }
            else
            {
                spdlog::warn("Session already established with {}, ignoring handshake", remotePeerID);
                return std::nullopt;
            }
        }
    }

    // Create new session if doesn't exist (always creates on handshake INIT due to reset above)
    auto &session = sessions[remotePeerID];
    if (!session)
    {
        spdlog::info("Creating new session for {} with role {}", remotePeerID,
                     (role == NoiseRole::Initiator ? "Initiator" : "Responder"));
        session = std::make_shared<NoiseSessionImpl>(remotePeerID, role, localStaticKey);
    }

    // Process handshake
    try
    {
        auto response = session->processHandshakeMessage(message);

        // Debug session establishment
        spdlog::info("=== SESSION ESTABLISHMENT DEBUG ===");
        spdlog::info("Session exists: {}", (session != nullptr));
        spdlog::info("Session isEstablished: {}", session->isSessionEstablished());
        spdlog::info("Session peerID: {}", session->getPeerID());
        spdlog::info("=== END SESSION ESTABLISHMENT DEBUG ===");

        if (session->isSessionEstablished() && onSessionEstablished_)
        {
            auto remoteKey = session->getRemoteStaticPublicKey();
            if (remoteKey)
                onSessionEstablished_(remotePeerID, *remoteKey);
        }
        return response;
    }
    catch (const std::exception &e)
    {
        spdlog::error("Handshake failed for {}: {}", remotePeerID, e.what());
        sessions.erase(remotePeerID);
        if (onSessionFailed_)
            onSessionFailed_(remotePeerID, e);
        throw;
    }
}

std::vector<uint8_t> NoiseSessionManager::encrypt(const std::vector<uint8_t> &plaintext, const std::string &peerID)
{
    auto session = getSession(peerID);
    if (!session)
    {
        throw std::runtime_error("Session not found");
    }

    return session->encrypt(plaintext);
}

std::vector<uint8_t> NoiseSessionManager::decrypt(const std::vector<uint8_t> &ciphertext, const std::string &peerID)
{
    auto session = getSession(peerID);
    if (!session)
    {
        throw std::runtime_error("Session not found");
    }

    return session->decrypt(ciphertext);
}

bool NoiseSessionManager::isSessionEstablished(const std::string &peerID) const
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    auto it = sessions.find(peerID);
    return it != sessions.end() && it->second->isSessionEstablished();
}

bool NoiseSessionManager::hasEstablishedSession(const std::string &peerID) const
{
    return isSessionEstablished(peerID);
}

std::vector<std::string> NoiseSessionManager::getEstablishedSessionIDs() const
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    std::vector<std::string> established;
    for (const auto &[peerID, session] : sessions)
    {
        if (session->isSessionEstablished())
        {
            established.push_back(peerID);
        }
    }
    return established;
}

std::optional<PublicKey> NoiseSessionManager::getRemoteStaticKey(const std::string &peerID) const
{
    auto session = getSession(peerID);
    if (!session)
    {
        return std::nullopt;
    }

    return session->getRemoteStaticPublicKey();
}

std::optional<std::vector<uint8_t>> NoiseSessionManager::getHandshakeHash(const std::string &peerID) const
{
    auto session = getSession(peerID);
    if (!session)
    {
        return std::nullopt;
    }

    return session->getHandshakeHash();
}

std::vector<std::pair<std::string, bool>> NoiseSessionManager::getSessionsNeedingRekey() const
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    std::vector<std::pair<std::string, bool>> needingRekey;
    for (const auto &[peerID, session] : sessions)
    {
        if (session->isSessionEstablished())
        {
            bool needsRekey = session->needsRenegotiation();
            needingRekey.emplace_back(peerID, needsRekey);
        }
    }
    return needingRekey;
}

void NoiseSessionManager::initiateRekey(const std::string &peerID)
{
    // Remove old session
    removeSession(peerID);

    // Initiate new handshake
    try
    {
        initiateHandshake(peerID);
    }
    catch (const std::exception &e)
    {
        spdlog::error("Failed to initiate rekey for {}: {}", peerID, e.what());
    }
}

void NoiseSessionManager::setOnSessionEstablished(std::function<void(const std::string &, const PublicKey &)> callback)
{
    onSessionEstablished_ = callback;
}

void NoiseSessionManager::setOnSessionFailed(std::function<void(const std::string &, const std::exception &)> callback)
{
    onSessionFailed_ = callback;
}

NoiseRole NoiseSessionManager::resolveRole(const std::string &localPeerID, const std::string &remotePeerID) const
{
    return (localPeerID < remotePeerID) ? NoiseRole::Initiator : NoiseRole::Responder;
}

} // namespace noise
} // namespace bitchat
