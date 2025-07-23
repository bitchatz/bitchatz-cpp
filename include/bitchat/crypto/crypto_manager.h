#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <openssl/evp.h>
#include <string>
#include <vector>

namespace bitchat
{

// CryptoManager: Handles encryption, signatures, and key management
class CryptoManager
{
public:
    CryptoManager();
    ~CryptoManager();

    // Initialize crypto subsystem
    bool initialize();

    // Cleanup crypto resources
    void cleanup();

    // Generate or load signing key pair
    bool generateOrLoadKeyPair(const std::string &keyFile);

    // Sign data with private key
    std::vector<uint8_t> signData(const std::vector<uint8_t> &data);

    // Get Curve25519 private key for Noise Protocol
    std::vector<uint8_t> getCurve25519PrivateKey() const;

private:
    EVP_PKEY *signingPrivateKey;
    mutable std::mutex cryptoMutex;

    // Helper functions
    EVP_PKEY *loadPrivateKey(const std::string &filename);
    void savePrivateKey(EVP_PKEY *pkey, const std::string &filename);
    std::vector<uint8_t> getPublicKeyBytes(EVP_PKEY *pkey) const;
};

} // namespace bitchat
