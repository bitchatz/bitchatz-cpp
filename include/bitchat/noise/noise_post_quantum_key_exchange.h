#pragma once

#include <vector>

namespace bitchat
{

class NoisePostQuantumKeyExchange
{
public:
    using PublicKey = std::vector<uint8_t>;
    using PrivateKey = std::vector<uint8_t>;
    using SharedSecret = std::vector<uint8_t>;

    virtual ~NoisePostQuantumKeyExchange() = default;

    // Generate a new key pair
    virtual std::pair<PublicKey, PrivateKey> generateKeyPair() = 0;

    // Encapsulate a shared secret using the remote public key
    virtual std::pair<SharedSecret, std::vector<uint8_t>> encapsulate(const PublicKey &remotePublicKey) = 0;

    // Decapsulate a shared secret using the local private key
    virtual SharedSecret decapsulate(const std::vector<uint8_t> &ciphertext, const PrivateKey &privateKey) = 0;

    // Get key sizes
    virtual size_t getPublicKeySize() const = 0;
    virtual size_t getPrivateKeySize() const = 0;
    virtual size_t getCiphertextSize() const = 0;
    virtual size_t getSharedSecretSize() const = 0;

    // Get algorithm name
    virtual std::string getAlgorithmName() const = 0;
};

} // namespace bitchat
