// Toda a implementação foi migrada para a biblioteca noise-c.
// Este header permanece apenas para tipos e compatibilidade de build.

#pragma once

#include <array>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace bitchat
{
namespace noise
{

// Basic Types

// 32-byte symmetric key
using SymmetricKey = std::array<uint8_t, 32>;

// 32-byte public key (Curve25519)
using PublicKey = std::array<uint8_t, 32>;

// 32-byte private key (Curve25519)
using PrivateKey = std::array<uint8_t, 32>;

// 32-byte shared secret
using SharedSecret = std::array<uint8_t, 32>;

// Session Types

enum class NoiseRole
{
    Initiator,
    Responder
};

// Security Constants

struct NoiseSecurityConstants
{
    // Maximum message size to prevent memory exhaustion
    static constexpr size_t maxMessageSize = 65535; // 64KB as per Noise spec

    // Maximum handshake message size
    static constexpr size_t maxHandshakeMessageSize = 2048; // 2KB to accommodate XX pattern

    // Session timeout - sessions older than this should be renegotiated
    static constexpr std::chrono::hours sessionTimeout{24}; // 24 hours

    // Maximum number of messages before rekey (2^64 - 1 is the nonce limit)
    static constexpr uint64_t maxMessagesPerSession = 1'000'000'000; // 1 billion messages

    // Handshake timeout - abandon incomplete handshakes
    static constexpr std::chrono::seconds handshakeTimeout{60}; // 1 minute

    // Maximum concurrent sessions per peer
    static constexpr size_t maxSessionsPerPeer = 3;

    // Rate limiting
    static constexpr size_t maxHandshakesPerMinute = 10;
    static constexpr size_t maxMessagesPerSecond = 100;

    // Global rate limiting (across all peers)
    static constexpr size_t maxGlobalHandshakesPerMinute = 30;
    static constexpr size_t maxGlobalMessagesPerSecond = 500;
};

// Security Errors

enum class NoiseSecurityError
{
    SessionExpired,
    SessionExhausted,
    MessageTooLarge,
    InvalidPeerID,
    InvalidChannelName,
    RateLimitExceeded,
    HandshakeTimeout
};

// Utility Functions

// SHA-256 hash function
std::vector<uint8_t> sha256(const std::vector<uint8_t> &data);
std::vector<uint8_t> sha256(const std::string &data);

} // namespace noise
} // namespace bitchat
