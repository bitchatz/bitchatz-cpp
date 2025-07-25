#pragma once

#include "bitchat/noise/noise_protocol.h"
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bitchat
{

class NoiseSession
{
public:
    virtual ~NoiseSession() = default;

    // Core encryption/decryption
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext) = 0;

    // Session state
    virtual bool isSessionEstablished() const = 0;
    virtual std::string getPeerID() const = 0;
    virtual std::optional<NoisePublicKey> getRemoteStaticPublicKey() const = 0;
    virtual std::optional<std::vector<uint8_t>> getHandshakeHash() const = 0;

    // Security features
    virtual bool needsRenegotiation() const = 0;
    virtual uint64_t getMessageCount() const = 0;
    virtual std::chrono::system_clock::time_point getLastActivityTime() const = 0;
    virtual bool handshakeInProgress() const = 0;

    // Handshake processing
    virtual std::optional<std::vector<uint8_t>> processHandshakeMessage(const std::vector<uint8_t> &message) = 0;
    virtual std::optional<std::vector<uint8_t>> startHandshake() = 0;
};

} // namespace bitchat
