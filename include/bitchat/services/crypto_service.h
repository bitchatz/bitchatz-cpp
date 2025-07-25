#pragma once

#include <mutex>
#include <string>
#include <vector>

namespace bitchat
{

class CryptoService
{
public:
    CryptoService();
    ~CryptoService();

    bool initialize();
    void cleanup();
    bool generateOrLoadKeyPair(const std::string &keyFile);
    std::vector<uint8_t> generateRandomBytes(size_t length);
    std::vector<uint8_t> sha256(const std::vector<uint8_t> &data);
    std::vector<uint8_t> sha256(const std::string &data);
    std::vector<uint8_t> signData(const std::vector<uint8_t> &data);
    std::vector<uint8_t> getCurve25519PrivateKey() const;

private:
    mutable std::mutex cryptoMutex;
    void *signingPrivateKey; // EVP_PKEY*

    // Private helper methods
    void *loadPrivateKey(const std::string &filename);
    void savePrivateKey(void *pkey, const std::string &filename);
    std::vector<uint8_t> getPublicKeyBytes(void *pkey) const;
};

} // namespace bitchat
