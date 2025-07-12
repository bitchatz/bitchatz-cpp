#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>

// Forward declaration for OpenSSL types
typedef struct evp_pkey_st EVP_PKEY;

namespace bitchat {

// CryptoManager: handles encryption, signatures, and key management
class CryptoManager {
public:
    CryptoManager();
    ~CryptoManager();

    // Initialize crypto subsystem
    bool initialize();
    
    // Cleanup crypto resources
    void cleanup();

    // Generate or load signing key pair
    bool generateOrLoadKeyPair(const std::string& keyFile = "bitchat_keypair.pem");
    
    // Sign data with private key
    std::vector<uint8_t> signData(const std::vector<uint8_t>& data);
    
    // Verify signature with peer's public key
    bool verifySignature(const std::vector<uint8_t>& data, 
                        const std::vector<uint8_t>& signature,
                        const std::string& peerId);
    
    // Add peer's public key (combined format from Swift - 96 bytes)
    bool addPeerPublicKey(const std::string& peerId, const std::vector<uint8_t>& combinedKeyData);
    
    // Get combined public key data (Swift format - 96 bytes)
    std::vector<uint8_t> getCombinedPublicKeyData() const;
    
    // Get public key bytes
    std::vector<uint8_t> getPublicKeyBytes() const;
    
    // Save peer public key to file
    void savePeerPublicKey(const std::string& peerId, const std::vector<uint8_t>& pubkey);
    
    // Check if we have a key for a peer
    bool hasPeerKey(const std::string& peerId) const;

private:
    EVP_PKEY* signingPrivateKey;
    std::map<std::string, EVP_PKEY*> peerSigningKeys;
    mutable std::mutex cryptoMutex;
    
    // Helper functions
    EVP_PKEY* loadPrivateKey(const std::string& filename);
    void savePrivateKey(EVP_PKEY* pkey, const std::string& filename);
    std::vector<uint8_t> getPublicKeyBytes(EVP_PKEY* pkey) const;
};

} // namespace bitchat 