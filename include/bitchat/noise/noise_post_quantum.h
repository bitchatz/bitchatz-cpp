#pragma once

#include "noise_protocol.h"
#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace bitchat
{
namespace noise
{

// Post-Quantum Cryptography Framework

/// Framework for integrating post-quantum algorithms with Noise Protocol
/// Currently a placeholder until PQ libraries are available in C++
template <typename PublicKeyType, typename PrivateKeyType, typename SharedSecretType>
class PostQuantumKeyExchange
{
public:
    /// Generate a new keypair
    static std::pair<PublicKeyType, PrivateKeyType> generateKeyPair();

    /// Derive shared secret (for initiator)
    static std::pair<SharedSecretType, std::vector<uint8_t>> encapsulate(const PublicKeyType &remotePublicKey);

    /// Derive shared secret (for responder)
    static SharedSecretType decapsulate(const std::vector<uint8_t> &ciphertext, const PrivateKeyType &privateKey);

    /// Get size requirements
    static constexpr size_t publicKeySize = 0;
    static constexpr size_t privateKeySize = 0;
    static constexpr size_t ciphertextSize = 0;
    static constexpr size_t sharedSecretSize = 0;
};

// Hybrid Key Exchange

/// Combines classical (Curve25519) with post-quantum algorithms
class HybridNoiseKeyExchange
{
public:
    enum class Algorithm
    {
        ClassicalOnly,  // Current: Curve25519 only
        HybridKyber768, // Future: Curve25519 + Kyber768
        HybridKyber1024 // Future: Curve25519 + Kyber1024
    };

    struct HybridPublicKey
    {
        PublicKey classical;
        std::optional<std::vector<uint8_t>> postQuantum; // Future: actual PQ public key

        std::vector<uint8_t> serialized() const;
    };

    struct HybridPrivateKey
    {
        PrivateKey classical;
        std::optional<std::vector<uint8_t>> postQuantum; // Future: actual PQ private key
    };

    struct HybridSharedSecret
    {
        SharedSecret classical;
        std::optional<std::vector<uint8_t>> postQuantum; // Future: actual PQ shared secret

        /// Combine both secrets using KDF
        SymmetricKey combinedSecret() const;
    };

    // Key Generation

    static std::pair<HybridPublicKey, HybridPrivateKey> generateKeyPair(Algorithm algorithm);

    // Key Agreement

    static HybridSharedSecret performKeyAgreement(const HybridPrivateKey &localPrivate,
                                                  const HybridPublicKey &remotePublic,
                                                  Algorithm algorithm);

    // Utility

    static std::string algorithmName(Algorithm algorithm);
    static bool isPostQuantum(Algorithm algorithm);
};

// Modified Noise Pattern for PQ

/// Extended Noise handshake pattern for post-quantum
/// Based on Noise PQ patterns: https://github.com/noiseprotocol/noise_pq_spec
struct NoisePQHandshakePattern
{
    // Pattern modifiers for PQ
    enum class Modifier
    {
        PQ1, // First message includes PQ KEM
        PQ2, // Second message includes PQ KEM
        PQ3  // Third message includes PQ KEM
    };

    // Example: XXpq1 pattern (XX with PQ in first message)
    // -> e, epq
    // <- e, ee, eepq, s, es
    // -> s, se

    // This would modify the Noise XX pattern to include
    // post-quantum key encapsulation material
};

// Migration Support

/// Helps transition from classical to post-quantum crypto
class NoiseProtocolMigration
{
public:
    enum class MigrationPhase
    {
        ClassicalOnly,  // Current state
        HybridOptional, // Support both, prefer hybrid
        HybridRequired, // Require hybrid mode
        PostQuantumOnly // Future: PQ only
    };

    struct MigrationConfig
    {
        MigrationPhase currentPhase;
        HybridNoiseKeyExchange::Algorithm preferredAlgorithm;
        std::vector<HybridNoiseKeyExchange::Algorithm> acceptedAlgorithms;
        std::optional<std::chrono::system_clock::time_point> migrationDeadline;
    };

    /// Check if a peer supports post-quantum
    static bool checkPQSupport(const std::string &peerVersion);

    /// Get migration configuration
    static MigrationConfig getMigrationConfig();
};

// Future Implementation Notes

/*
 Post-Quantum Integration Plan:

 1. Wait for stable C++ PQ libraries (e.g., liboqs)
 2. Implement Kyber768/1024 wrapper conforming to PostQuantumKeyExchange
 3. Update Noise handshake to support hybrid mode
 4. Add capability negotiation in protocol
 5. Implement gradual rollout with fallback

 Challenges:
 - Increased message sizes (Kyber768 public key ~1184 bytes)
 - Performance impact on mobile devices
 - Battery usage considerations
 - Backward compatibility
 - Library availability and maintenance

 Timeline estimate:
 - PQ libraries stable in C++: 2025-2026
 - Initial hybrid implementation: 2026
 - Full deployment: 2027+
 */

// Testing Support

#ifdef DEBUG
/// Mock PQ implementation for testing
class MockPostQuantumKeyExchange
{
public:
    using PublicKey = std::vector<uint8_t>;
    using PrivateKey = std::vector<uint8_t>;
    using SharedSecret = std::vector<uint8_t>;

    static std::pair<PublicKey, PrivateKey> generateKeyPair();
    static std::pair<SharedSecret, std::vector<uint8_t>> encapsulate(const PublicKey &remotePublicKey);
    static SharedSecret decapsulate(const std::vector<uint8_t> &ciphertext, const PrivateKey &privateKey);

    static constexpr size_t publicKeySize = 800;
    static constexpr size_t privateKeySize = 1632;
    static constexpr size_t ciphertextSize = 1088;
    static constexpr size_t sharedSecretSize = 32;
};
#endif

} // namespace noise
} // namespace bitchat
