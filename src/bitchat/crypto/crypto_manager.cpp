#include "bitchat/crypto/crypto_manager.h"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <spdlog/spdlog.h>

namespace bitchat
{

CryptoManager::CryptoManager()
    : signingPrivateKey(nullptr)
{
    //
}

CryptoManager::~CryptoManager()
{
    cleanup();
}

bool CryptoManager::initialize()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return true;
}

void CryptoManager::cleanup()
{
    std::lock_guard<std::mutex> lock(cryptoMutex);

    if (signingPrivateKey)
    {
        EVP_PKEY_free(signingPrivateKey);
        signingPrivateKey = nullptr;
    }

    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();
}

bool CryptoManager::generateOrLoadKeyPair(const std::string &keyFile)
{
    std::lock_guard<std::mutex> lock(cryptoMutex);

    // Try to load existing key
    signingPrivateKey = loadPrivateKey(keyFile);
    if (signingPrivateKey)
    {
        return true;
    }

    // Generate new Ed25519 key pair
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx)
    {
        spdlog::error("Error creating Ed25519 key context");
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        spdlog::error("Error initializing key generation");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_keygen(ctx, &signingPrivateKey) <= 0)
    {
        spdlog::error("Error generating private key");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

    // Save the key
    savePrivateKey(signingPrivateKey, keyFile);

    return true;
}

std::vector<uint8_t> CryptoManager::signData(const std::vector<uint8_t> &data)
{
    std::lock_guard<std::mutex> lock(cryptoMutex);

    if (!signingPrivateKey)
    {
        spdlog::error("Private key not available for signing");
        return std::vector<uint8_t>();
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        spdlog::error("Error creating signature context");
        return std::vector<uint8_t>();
    }

    size_t sigLen = 0;
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, signingPrivateKey) <= 0)
    {
        spdlog::error("Error initializing signature");
        EVP_MD_CTX_free(ctx);
        return std::vector<uint8_t>();
    }

    // Calculate signature size
    if (EVP_DigestSign(ctx, nullptr, &sigLen, data.data(), data.size()) <= 0)
    {
        spdlog::error("Error calculating signature size");
        EVP_MD_CTX_free(ctx);
        return std::vector<uint8_t>();
    }

    // Create signature
    std::vector<uint8_t> signature(sigLen);
    if (EVP_DigestSign(ctx, signature.data(), &sigLen, data.data(), data.size()) <= 0)
    {
        spdlog::error("Error creating signature");
        EVP_MD_CTX_free(ctx);
        return std::vector<uint8_t>();
    }

    EVP_MD_CTX_free(ctx);

    // Resize to exact size (Ed25519 = 64 bytes)
    signature.resize(64);
    return signature;
}

// Private helper functions
EVP_PKEY *CryptoManager::loadPrivateKey(const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open())
    {
        return nullptr;
    }

    std::string pemData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    BIO *bio = BIO_new_mem_buf(pemData.c_str(), pemData.length());
    if (!bio)
    {
        return nullptr;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    return pkey;
}

void CryptoManager::savePrivateKey(EVP_PKEY *pkey, const std::string &filename)
{
    if (!pkey)
    {
        return;
    }

    BIO *bio = BIO_new_file(filename.c_str(), "wb");
    if (!bio)
    {
        return;
    }

    PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(bio);
}

std::vector<uint8_t> CryptoManager::getPublicKeyBytes(EVP_PKEY *pkey) const
{
    if (!pkey)
    {
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> pubkey(32);
    size_t len = pubkey.size();
    EVP_PKEY_get_raw_public_key(pkey, pubkey.data(), &len);
    pubkey.resize(len);
    return pubkey;
}

std::vector<uint8_t> CryptoManager::getCurve25519PrivateKey() const
{
    std::lock_guard<std::mutex> lock(cryptoMutex);

    if (!signingPrivateKey)
    {
        spdlog::error("No signing private key available");
        return std::vector<uint8_t>();
    }

    // Extract raw private key bytes from Ed25519 key
    std::vector<uint8_t> ed25519PrivateKey(32);
    size_t len = ed25519PrivateKey.size();

    if (EVP_PKEY_get_raw_private_key(signingPrivateKey, ed25519PrivateKey.data(), &len) != 1)
    {
        spdlog::error("Failed to extract private key bytes");
        return std::vector<uint8_t>();
    }

    ed25519PrivateKey.resize(len);

    // Convert Ed25519 private key to Curve25519 private key
    // Ed25519 uses a different curve, so we need to apply the proper conversion
    std::vector<uint8_t> curve25519PrivateKey(32);

    // The conversion involves:
    // 1. Clamping the key (setting/clearing specific bits)
    // 2. This is the standard conversion from Ed25519 to Curve25519
    std::copy(ed25519PrivateKey.begin(), ed25519PrivateKey.end(), curve25519PrivateKey.begin());

    // Clamp the key for Curve25519 (set bit 0, clear bit 255, set bit 254)
    curve25519PrivateKey[0] &= 248;  // Clear bits 0-2
    curve25519PrivateKey[31] &= 127; // Clear bit 255
    curve25519PrivateKey[31] |= 64;  // Set bit 254

    return curve25519PrivateKey;
}

} // namespace bitchat
