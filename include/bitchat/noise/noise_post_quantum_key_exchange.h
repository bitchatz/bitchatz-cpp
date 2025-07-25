#pragma once

#include "bitchat/noise/noise_protocol.h"
#include <cstdint>
#include <string>
#include <vector>

namespace bitchat
{

class NoisePostQuantumKeyExchange
{
public:
    virtual ~NoisePostQuantumKeyExchange() = default;

    // Generate a new key pair
    virtual std::pair<NoisePublicKey, NoisePrivateKey> generateKeyPair() = 0;

    // Encapsulate a shared secret using the remote public key
    virtual std::pair<NoiseSharedSecret, std::vector<uint8_t>> encapsulate(const NoisePublicKey &remotePublicKey) = 0;

    // Decapsulate a shared secret using the local private key
    virtual NoiseSharedSecret decapsulate(const std::vector<uint8_t> &ciphertext, const NoisePrivateKey &privateKey) = 0;

    // Get key sizes
    virtual size_t getPublicKeySize() const = 0;
    virtual size_t getPrivateKeySize() const = 0;
    virtual size_t getCiphertextSize() const = 0;
    virtual size_t getSharedSecretSize() const = 0;

    // Get algorithm name
    virtual std::string getAlgorithmName() const = 0;
};

} // namespace bitchat
