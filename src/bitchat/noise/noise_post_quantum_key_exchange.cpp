#include "bitchat/noise/noise_post_quantum_key_exchange.h"
#include "bitchat/noise/noise_security_error.h"
#include <openssl/rand.h>
#include <stdexcept>

namespace bitchat
{

class NoisePostQuantumKeyExchangeDefault : public NoisePostQuantumKeyExchange
{
public:
    std::pair<NoisePublicKey, NoisePrivateKey> generateKeyPair() override
    {
        NoisePublicKey publicKey;
        NoisePrivateKey privateKey;

        if (RAND_bytes(publicKey.data(), static_cast<int>(publicKey.size())) != 1)
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to generate public key");
        }

        if (RAND_bytes(privateKey.data(), static_cast<int>(privateKey.size())) != 1)
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to generate private key");
        }

        return {publicKey, privateKey};
    }

    std::pair<NoiseSharedSecret, std::vector<uint8_t>> encapsulate([[maybe_unused]] const NoisePublicKey &remotePublicKey) override
    {
        if (remotePublicKey.size() != getPublicKeySize())
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::InvalidPeerID, "Invalid public key size");
        }

        NoiseSharedSecret sharedSecret;
        std::vector<uint8_t> ciphertext(getCiphertextSize());

        if (RAND_bytes(sharedSecret.data(), static_cast<int>(sharedSecret.size())) != 1)
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to generate shared secret");
        }

        if (RAND_bytes(ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to generate ciphertext");
        }

        return {sharedSecret, ciphertext};
    }

    NoiseSharedSecret decapsulate(const std::vector<uint8_t> &ciphertext, [[maybe_unused]] const NoisePrivateKey &privateKey) override
    {
        if (ciphertext.size() != getCiphertextSize())
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::InvalidHandshakeMessage, "Invalid ciphertext size");
        }

        if (privateKey.size() != getPrivateKeySize())
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::InvalidPeerID, "Invalid private key size");
        }

        NoiseSharedSecret sharedSecret;

        if (RAND_bytes(sharedSecret.data(), static_cast<int>(sharedSecret.size())) != 1)
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to generate shared secret");
        }

        return sharedSecret;
    }

    size_t getPublicKeySize() const override
    {
        return 32; // NoisePublicKey size
    }

    size_t getPrivateKeySize() const override
    {
        return 32; // NoisePrivateKey size
    }

    size_t getCiphertextSize() const override
    {
        return 1088;
    }

    size_t getSharedSecretSize() const override
    {
        return 32; // NoiseSharedSecret size
    }

    std::string getAlgorithmName() const override
    {
        return "DefaultPQ";
    }
};

} // namespace bitchat
