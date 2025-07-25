#pragma once

#include "bitchat/noise/noise_post_quantum_key_exchange.h"
#include "bitchat/noise/noise_protocol.h"
#include <memory>

namespace bitchat
{

class NoiseHybridKeyExchange
{
public:
    explicit NoiseHybridKeyExchange(std::shared_ptr<NoisePostQuantumKeyExchange> pqKex);

    // Generate hybrid key pair (classical + post-quantum)
    std::pair<NoisePublicKey, NoisePrivateKey> generateKeyPair();

    // Perform hybrid key exchange
    std::pair<NoiseSharedSecret, std::vector<uint8_t>> encapsulate(const NoisePublicKey &remotePublicKey);

    // Decapsulate hybrid shared secret
    NoiseSharedSecret decapsulate(const std::vector<uint8_t> &ciphertext, const NoisePrivateKey &privateKey);

    // Get combined key sizes
    size_t getPublicKeySize() const;
    size_t getPrivateKeySize() const;
    size_t getCiphertextSize() const;
    size_t getSharedSecretSize() const;

    // Get algorithm name
    std::string getAlgorithmName() const;

private:
    std::shared_ptr<NoisePostQuantumKeyExchange> pqKex;

    // Classical key sizes (Curve25519)
    static constexpr size_t classicalPublicKeySize = 32;
    static constexpr size_t classicalPrivateKeySize = 32;
    static constexpr size_t classicalSharedSecretSize = 32;
};

} // namespace bitchat
