#include "bitchat/services/crypto_service.h"
#include <fstream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>

namespace bitchat
{

CryptoService::CryptoService()
    : signingPrivateKey(nullptr)
{
    // Pass
}

CryptoService::~CryptoService()
{
    cleanup();
}

bool CryptoService::initialize()
{
    // Generate or load key pair
    if (!generateOrLoadKeyPair("bitchat-pk.pem"))
    {
        spdlog::error("Failed to generate or load key pair");
        return false;
    }

    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    return true;
}

void CryptoService::cleanup()
{
    std::lock_guard<std::mutex> lock(cryptoMutex);

    if (signingPrivateKey)
    {
        EVP_PKEY_free(static_cast<EVP_PKEY *>(signingPrivateKey));
        signingPrivateKey = nullptr;
    }

    EVP_cleanup();
    ERR_free_strings();
}

bool CryptoService::generateOrLoadKeyPair(const std::string &keyFile)
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

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        spdlog::error("Error generating private key");
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    signingPrivateKey = pkey;
    EVP_PKEY_CTX_free(ctx);

    // Save the key
    savePrivateKey(signingPrivateKey, keyFile);

    return true;
}

std::vector<uint8_t> CryptoService::generateRandomBytes(size_t length)
{
    std::vector<uint8_t> bytes(length);
    if (RAND_bytes(bytes.data(), static_cast<int>(length)) != 1)
    {
        return {};
    }
    return bytes;
}

std::vector<uint8_t> CryptoService::sha256(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return {};
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hashLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

std::vector<uint8_t> CryptoService::sha256(const std::string &data)
{
    std::vector<uint8_t> dataBytes(data.begin(), data.end());
    return sha256(dataBytes);
}

std::vector<uint8_t> CryptoService::signData(const std::vector<uint8_t> &data)
{
    std::lock_guard<std::mutex> lock(cryptoMutex);

    if (!signingPrivateKey)
    {
        spdlog::error("No signing key available");
        return {};
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        spdlog::error("Failed to create digest context");
        return {};
    }

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, static_cast<EVP_PKEY *>(signingPrivateKey)) <= 0)
    {
        spdlog::error("Failed to initialize signing");
        EVP_MD_CTX_free(ctx);
        return {};
    }

    size_t signatureLen = 0;
    if (EVP_DigestSign(ctx, nullptr, &signatureLen, data.data(), data.size()) <= 0)
    {
        spdlog::error("Failed to get signature length");
        EVP_MD_CTX_free(ctx);
        return {};
    }

    std::vector<uint8_t> signature(signatureLen);
    if (EVP_DigestSign(ctx, signature.data(), &signatureLen, data.data(), data.size()) <= 0)
    {
        spdlog::error("Failed to create signature");
        EVP_MD_CTX_free(ctx);
        return {};
    }

    EVP_MD_CTX_free(ctx);
    return signature;
}

std::vector<uint8_t> CryptoService::getCurve25519PrivateKey() const
{
    std::lock_guard<std::mutex> lock(cryptoMutex);

    if (!signingPrivateKey)
    {
        return {};
    }

    // For now, return a dummy Curve25519 key
    // In a real implementation, you would convert the Ed25519 key to Curve25519
    std::vector<uint8_t> curve25519PrivateKey(32);
    if (RAND_bytes(curve25519PrivateKey.data(), 32) != 1)
    {
        return {};
    }

    return curve25519PrivateKey;
}

void *CryptoService::loadPrivateKey(const std::string &filename)
{
    FILE *fp = fopen(filename.c_str(), "r");
    if (!fp)
    {
        return nullptr;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!pkey)
    {
        spdlog::error("Failed to load private key from: {}", filename);
        return nullptr;
    }

    spdlog::info("Loaded private key from: {}", filename);
    return pkey;
}

void CryptoService::savePrivateKey(void *pkey, const std::string &filename)
{
    if (!pkey)
    {
        return;
    }

    FILE *fp = fopen(filename.c_str(), "w");
    if (!fp)
    {
        spdlog::error("Failed to open key file for writing: {}", filename);
        return;
    }

    if (PEM_write_PrivateKey(fp, static_cast<EVP_PKEY *>(pkey), nullptr, nullptr, 0, nullptr, nullptr) <= 0)
    {
        spdlog::error("Failed to write private key to file");
        fclose(fp);
        return;
    }

    fclose(fp);
    spdlog::info("Saved private key to: {}", filename);
}

std::vector<uint8_t> CryptoService::getPublicKeyBytes(void *pkey) const
{
    if (!pkey)
    {
        return {};
    }

    size_t keyLen = 0;
    if (EVP_PKEY_get_raw_public_key(static_cast<EVP_PKEY *>(pkey), nullptr, &keyLen) <= 0)
    {
        return {};
    }

    std::vector<uint8_t> publicKey(keyLen);
    if (EVP_PKEY_get_raw_public_key(static_cast<EVP_PKEY *>(pkey), publicKey.data(), &keyLen) <= 0)
    {
        return {};
    }

    return publicKey;
}

} // namespace bitchat
