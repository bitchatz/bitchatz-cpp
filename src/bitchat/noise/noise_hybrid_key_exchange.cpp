#include "bitchat/noise/noise_hybrid_key_exchange.h"
#include "bitchat/noise/noise_security_error.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <spdlog/spdlog.h>

namespace bitchat
{

NoiseHybridKeyExchange::NoiseHybridKeyExchange(std::shared_ptr<NoisePostQuantumKeyExchange> pqKex)
    : pqKex(pqKex)
{
    if (!pqKex)
    {
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Post-quantum key exchange is required");
    }
}

std::pair<NoisePublicKey, NoisePrivateKey> NoiseHybridKeyExchange::generateKeyPair()
{
    // Generate classical key pair (Curve25519)
    EVP_PKEY *classicalKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, nullptr, 0);
    if (!classicalKey)
    {
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to create classical key");
    }

    // Generate random classical private key
    std::vector<uint8_t> classicalPrivateKey(classicalPrivateKeySize);
    if (RAND_bytes(classicalPrivateKey.data(), static_cast<int>(classicalPrivateKey.size())) != 1)
    {
        EVP_PKEY_free(classicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to generate classical private key");
    }

    // Set the private key
    if (EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, classicalPrivateKey.data(), classicalPrivateKey.size()) != classicalKey)
    {
        EVP_PKEY_free(classicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to set classical private key");
    }

    // Get the public key
    size_t publicKeyLen = classicalPublicKeySize;
    std::vector<uint8_t> classicalPublicKey(publicKeyLen);
    if (EVP_PKEY_get_raw_public_key(classicalKey, classicalPublicKey.data(), &publicKeyLen) != 1)
    {
        EVP_PKEY_free(classicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to get classical public key");
    }

    EVP_PKEY_free(classicalKey);

    // Generate post-quantum key pair
    // auto [pqPublicKey, pqPrivateKey] = pqKex->generateKeyPair();

    // For hybrid, we'll combine the classical and post-quantum keys
    // Since both are 32 bytes, we'll use the classical keys for now
    NoisePublicKey hybridPublicKey;
    NoisePrivateKey hybridPrivateKey;

    // Copy classical keys to the hybrid keys
    std::copy(classicalPublicKey.begin(), classicalPublicKey.end(), hybridPublicKey.begin());
    std::copy(classicalPrivateKey.begin(), classicalPrivateKey.end(), hybridPrivateKey.begin());

    return {hybridPublicKey, hybridPrivateKey};
}

std::pair<NoiseSharedSecret, std::vector<uint8_t>> NoiseHybridKeyExchange::encapsulate(const NoisePublicKey &remotePublicKey)
{
    if (remotePublicKey.size() != getPublicKeySize())
    {
        throw NoiseSecurityError(NoiseSecurityErrorType::InvalidPeerID, "Invalid remote public key size");
    }

    // Extract classical and post-quantum parts
    std::vector<uint8_t> classicalRemoteKey(remotePublicKey.begin(), remotePublicKey.end());
    std::vector<uint8_t> pqRemoteKey(remotePublicKey.begin(), remotePublicKey.end()); // Same for now

    // Perform classical key exchange
    EVP_PKEY *classicalKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, nullptr, 0);
    if (!classicalKey)
    {
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to create classical key");
    }

    // Generate ephemeral classical key pair
    std::vector<uint8_t> ephemeralPrivateKey(classicalPrivateKeySize);
    if (RAND_bytes(ephemeralPrivateKey.data(), static_cast<int>(ephemeralPrivateKey.size())) != 1)
    {
        EVP_PKEY_free(classicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to generate ephemeral private key");
    }

    if (EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, ephemeralPrivateKey.data(), ephemeralPrivateKey.size()) != classicalKey)
    {
        EVP_PKEY_free(classicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to set ephemeral private key");
    }

    // Get ephemeral public key
    size_t ephemeralPublicKeyLen = classicalPublicKeySize;
    std::vector<uint8_t> ephemeralPublicKey(ephemeralPublicKeyLen);
    if (EVP_PKEY_get_raw_public_key(classicalKey, ephemeralPublicKey.data(), &ephemeralPublicKeyLen) != 1)
    {
        EVP_PKEY_free(classicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to get ephemeral public key");
    }

    // Create remote key
    EVP_PKEY *remoteClassicalKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, classicalRemoteKey.data(), classicalRemoteKey.size());
    if (!remoteClassicalKey)
    {
        EVP_PKEY_free(classicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::InvalidPeerID, "Failed to create remote classical key");
    }

    // Perform classical key exchange
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(classicalKey, nullptr);
    if (!ctx)
    {
        EVP_PKEY_free(classicalKey);
        EVP_PKEY_free(remoteClassicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to create key exchange context");
    }

    if (EVP_PKEY_derive_init(ctx) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(classicalKey);
        EVP_PKEY_free(remoteClassicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to initialize key derivation");
    }

    if (EVP_PKEY_derive_set_peer(ctx, remoteClassicalKey) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(classicalKey);
        EVP_PKEY_free(remoteClassicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to set peer key");
    }

    size_t classicalSharedSecretLen = classicalSharedSecretSize;
    std::vector<uint8_t> classicalSharedSecret(classicalSharedSecretLen);
    if (EVP_PKEY_derive(ctx, classicalSharedSecret.data(), &classicalSharedSecretLen) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(classicalKey);
        EVP_PKEY_free(remoteClassicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to derive classical shared secret");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(classicalKey);
    EVP_PKEY_free(remoteClassicalKey);

    // Perform post-quantum key exchange
    NoisePublicKey pqRemoteKeyArray;
    std::copy(pqRemoteKey.begin(), pqRemoteKey.end(), pqRemoteKeyArray.begin());
    auto [pqSharedSecret, pqCiphertext] = pqKex->encapsulate(pqRemoteKeyArray);

    // Combine shared secrets (simplified - just use classical for now)
    NoiseSharedSecret combinedSharedSecret;
    std::copy(classicalSharedSecret.begin(), classicalSharedSecret.end(), combinedSharedSecret.begin());

    // Combine ciphertexts
    std::vector<uint8_t> combinedCiphertext;
    combinedCiphertext.reserve(classicalPublicKeySize + pqKex->getCiphertextSize());
    combinedCiphertext.insert(combinedCiphertext.end(), ephemeralPublicKey.begin(), ephemeralPublicKey.end());
    combinedCiphertext.insert(combinedCiphertext.end(), pqCiphertext.begin(), pqCiphertext.end());

    return {combinedSharedSecret, combinedCiphertext};
}

NoiseSharedSecret NoiseHybridKeyExchange::decapsulate(const std::vector<uint8_t> &ciphertext, const NoisePrivateKey &privateKey)
{
    if (ciphertext.size() != getCiphertextSize())
    {
        throw NoiseSecurityError(NoiseSecurityErrorType::InvalidHandshakeMessage, "Invalid ciphertext size");
    }

    if (privateKey.size() != getPrivateKeySize())
    {
        throw NoiseSecurityError(NoiseSecurityErrorType::InvalidPeerID, "Invalid private key size");
    }

    // Extract classical and post-quantum parts
    std::vector<uint8_t> ephemeralPublicKey(ciphertext.begin(), ciphertext.begin() + classicalPublicKeySize);
    std::vector<uint8_t> pqCiphertext(ciphertext.begin() + classicalPublicKeySize, ciphertext.end());

    std::vector<uint8_t> classicalPrivateKey(privateKey.begin(), privateKey.end());
    std::vector<uint8_t> pqPrivateKey(privateKey.begin(), privateKey.end()); // Same for now

    // Perform classical key exchange
    EVP_PKEY *classicalKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, classicalPrivateKey.data(), classicalPrivateKey.size());
    if (!classicalKey)
    {
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to create classical key");
    }

    EVP_PKEY *remoteClassicalKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, ephemeralPublicKey.data(), ephemeralPublicKey.size());
    if (!remoteClassicalKey)
    {
        EVP_PKEY_free(classicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::InvalidPeerID, "Failed to create remote classical key");
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(classicalKey, nullptr);
    if (!ctx)
    {
        EVP_PKEY_free(classicalKey);
        EVP_PKEY_free(remoteClassicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to create key exchange context");
    }

    if (EVP_PKEY_derive_init(ctx) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(classicalKey);
        EVP_PKEY_free(remoteClassicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to initialize key derivation");
    }

    if (EVP_PKEY_derive_set_peer(ctx, remoteClassicalKey) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(classicalKey);
        EVP_PKEY_free(remoteClassicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to set peer key");
    }

    size_t classicalSharedSecretLen = classicalSharedSecretSize;
    std::vector<uint8_t> classicalSharedSecret(classicalSharedSecretLen);
    if (EVP_PKEY_derive(ctx, classicalSharedSecret.data(), &classicalSharedSecretLen) != 1)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(classicalKey);
        EVP_PKEY_free(remoteClassicalKey);
        throw NoiseSecurityError(NoiseSecurityErrorType::KeyGenerationFailed, "Failed to derive classical shared secret");
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(classicalKey);
    EVP_PKEY_free(remoteClassicalKey);

    // Perform post-quantum key exchange
    // auto pqSharedSecret = pqKex->decapsulate(pqCiphertext, privateKey);

    // Combine shared secrets (simplified - just use classical for now)
    NoiseSharedSecret combinedSharedSecret;
    std::copy(classicalSharedSecret.begin(), classicalSharedSecret.end(), combinedSharedSecret.begin());

    return combinedSharedSecret;
}

size_t NoiseHybridKeyExchange::getPublicKeySize() const
{
    return classicalPublicKeySize + pqKex->getPublicKeySize();
}

size_t NoiseHybridKeyExchange::getPrivateKeySize() const
{
    return classicalPrivateKeySize + pqKex->getPrivateKeySize();
}

size_t NoiseHybridKeyExchange::getCiphertextSize() const
{
    return classicalPublicKeySize + pqKex->getCiphertextSize();
}

size_t NoiseHybridKeyExchange::getSharedSecretSize() const
{
    return classicalSharedSecretSize + pqKex->getSharedSecretSize();
}

std::string NoiseHybridKeyExchange::getAlgorithmName() const
{
    return "Hybrid-" + pqKex->getAlgorithmName();
}

} // namespace bitchat
