#include "bitchat/noise/noise_post_quantum_key_exchange.h"
#include "bitchat/noise/noise_security_error.h"
#include <openssl/rand.h>
#include <stdexcept>

namespace bitchat
{

class NoisePostQuantumKeyExchangeDefault : public NoisePostQuantumKeyExchange
{
public:
    std::pair<PublicKey, PrivateKey> generateKeyPair() override
    {
        PublicKey publicKey(getPublicKeySize());
        PrivateKey privateKey(getPrivateKeySize());

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

    std::pair<SharedSecret, std::vector<uint8_t>> encapsulate(const PublicKey &remotePublicKey) override
    {
        if (remotePublicKey.size() != getPublicKeySize())
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::InvalidPeerID, "Invalid public key size");
        }

        SharedSecret sharedSecret(getSharedSecretSize());
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

    SharedSecret decapsulate(const std::vector<uint8_t> &ciphertext, const PrivateKey &privateKey) override
    {
        if (ciphertext.size() != getCiphertextSize())
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::InvalidHandshakeMessage, "Invalid ciphertext size");
        }

        if (privateKey.size() != getPrivateKeySize())
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::InvalidPeerID, "Invalid private key size");
        }

        SharedSecret sharedSecret(getSharedSecretSize());

        if (RAND_bytes(sharedSecret.data(), static_cast<int>(sharedSecret.size())) != 1)
        {
            throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to generate shared secret");
        }

        return sharedSecret;
    }

    size_t getPublicKeySize() const override
    {
        return 800;
    }

    size_t getPrivateKeySize() const override
    {
        return 1632;
    }

    size_t getCiphertextSize() const override
    {
        return 1088;
    }

    size_t getSharedSecretSize() const override
    {
        return 32;
    }

    std::string getAlgorithmName() const override
    {
        return "DefaultPQ";
    }
};

} // namespace bitchat
