#include "bitchat/crypto/crypto_manager.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <algorithm>

namespace bitchat {

CryptoManager::CryptoManager() : signingPrivateKey(nullptr) {
}

CryptoManager::~CryptoManager() {
    cleanup();
}

bool CryptoManager::initialize() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    return true;
}

void CryptoManager::cleanup() {
    std::lock_guard<std::mutex> lock(cryptoMutex);
    
    if (signingPrivateKey) {
        EVP_PKEY_free(signingPrivateKey);
        signingPrivateKey = nullptr;
    }
    
    // Clean up peer keys
    for (auto& pair : peerSigningKeys) {
        if (pair.second) {
            EVP_PKEY_free(pair.second);
        }
    }
    peerSigningKeys.clear();
    
    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();
}

bool CryptoManager::generateOrLoadKeyPair(const std::string& keyFile) {
    std::lock_guard<std::mutex> lock(cryptoMutex);
    
    // Try to load existing key
    signingPrivateKey = loadPrivateKey(keyFile);
    if (signingPrivateKey) {
        return true;
    }
    
    // Generate new Ed25519 key pair
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        std::cerr << "Error creating Ed25519 key context" << std::endl;
        return false;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error initializing key generation" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    if (EVP_PKEY_keygen(ctx, &signingPrivateKey) <= 0) {
        std::cerr << "Error generating private key" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // Save the key
    savePrivateKey(signingPrivateKey, keyFile);
    
    return true;
}

std::vector<uint8_t> CryptoManager::signData(const std::vector<uint8_t>& data) {
    std::lock_guard<std::mutex> lock(cryptoMutex);
    
    if (!signingPrivateKey) {
        std::cerr << "Private key not available for signing" << std::endl;
        return std::vector<uint8_t>();
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating signature context" << std::endl;
        return std::vector<uint8_t>();
    }
    
    size_t sigLen = 0;
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, signingPrivateKey) <= 0) {
        std::cerr << "Error initializing signature" << std::endl;
        EVP_MD_CTX_free(ctx);
        return std::vector<uint8_t>();
    }
    
    // Calculate signature size
    if (EVP_DigestSign(ctx, nullptr, &sigLen, data.data(), data.size()) <= 0) {
        std::cerr << "Error calculating signature size" << std::endl;
        EVP_MD_CTX_free(ctx);
        return std::vector<uint8_t>();
    }
    
    // Create signature
    std::vector<uint8_t> signature(sigLen);
    if (EVP_DigestSign(ctx, signature.data(), &sigLen, data.data(), data.size()) <= 0) {
        std::cerr << "Error creating signature" << std::endl;
        EVP_MD_CTX_free(ctx);
        return std::vector<uint8_t>();
    }
    
    EVP_MD_CTX_free(ctx);
    
    // Resize to exact size (Ed25519 = 64 bytes)
    signature.resize(64);
    return signature;
}

bool CryptoManager::verifySignature(const std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& signature,
                                   const std::string& peerId) {
    std::lock_guard<std::mutex> lock(cryptoMutex);
    
    auto it = peerSigningKeys.find(peerId);
    if (it == peerSigningKeys.end()) {
        return false; // Key not available yet
    }
    
    EVP_PKEY* peerKey = it->second;
    if (!peerKey) {
        return false;
    }
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Error creating verification context" << std::endl;
        return false;
    }
    
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, peerKey) <= 0) {
        std::cerr << "Error initializing verification" << std::endl;
        EVP_MD_CTX_free(ctx);
        return false;
    }
    
    int result = EVP_DigestVerify(ctx, signature.data(), signature.size(),
                                 data.data(), data.size());
    EVP_MD_CTX_free(ctx);
    
    return result == 1;
}

bool CryptoManager::addPeerPublicKey(const std::string& peerId, const std::vector<uint8_t>& combinedKeyData) {
    if (combinedKeyData.size() != 96) {
        std::cerr << "Invalid combined key data size: " << combinedKeyData.size() << " (expected 96)" << std::endl;
        return false;
    }
    
    // Extract signing key (middle 32 bytes)
    std::vector<uint8_t> signingKeyData(combinedKeyData.begin() + 32, combinedKeyData.begin() + 64);
    
    std::lock_guard<std::mutex> lock(cryptoMutex);
    
    // Replace existing key if present
    if (peerSigningKeys.find(peerId) != peerSigningKeys.end()) {
        EVP_PKEY_free(peerSigningKeys[peerId]);
    }
    
    // Load received public key
    EVP_PKEY* peerKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                    signingKeyData.data(), signingKeyData.size());
    if (peerKey) {
        peerSigningKeys[peerId] = peerKey;
        return true;
    }
    
    return false;
}

std::vector<uint8_t> CryptoManager::getCombinedPublicKeyData() const {
    std::vector<uint8_t> data;
    
    // For Swift compatibility, use the same key for all three purposes
    // Swift uses: 32 bytes (key agreement) + 32 bytes (signing) + 32 bytes (identity)
    std::vector<uint8_t> pubkey = getPublicKeyBytes();
    
    // Repeat the same key for the three fields (96 bytes total)
    data.insert(data.end(), pubkey.begin(), pubkey.end()); // Key agreement (32 bytes)
    data.insert(data.end(), pubkey.begin(), pubkey.end()); // Signing (32 bytes)
    data.insert(data.end(), pubkey.begin(), pubkey.end()); // Identity (32 bytes)
    
    return data;
}

std::vector<uint8_t> CryptoManager::getPublicKeyBytes() const {
    if (!signingPrivateKey) {
        return std::vector<uint8_t>();
    }
    return getPublicKeyBytes(signingPrivateKey);
}

void CryptoManager::savePeerPublicKey(const std::string& peerId, const std::vector<uint8_t>& pubkey) {
    std::ofstream file("peers_keys.txt", std::ios::app);
    if (file.is_open()) {
        file << peerId << " ";
        for (auto byte : pubkey) {
            file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        file << std::endl;
    }
}

bool CryptoManager::hasPeerKey(const std::string& peerId) const {
    std::lock_guard<std::mutex> lock(cryptoMutex);
    return peerSigningKeys.find(peerId) != peerSigningKeys.end();
}

// Private helper functions
EVP_PKEY* CryptoManager::loadPrivateKey(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return nullptr;
    }
    
    std::string pemData((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    
    BIO* bio = BIO_new_mem_buf(pemData.c_str(), pemData.length());
    if (!bio) {
        return nullptr;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    return pkey;
}

void CryptoManager::savePrivateKey(EVP_PKEY* pkey, const std::string& filename) {
    if (!pkey) {
        return;
    }
    
    BIO* bio = BIO_new_file(filename.c_str(), "wb");
    if (!bio) {
        return;
    }
    
    PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    BIO_free(bio);
}

std::vector<uint8_t> CryptoManager::getPublicKeyBytes(EVP_PKEY* pkey) const {
    if (!pkey) {
        return std::vector<uint8_t>();
    }
    
    std::vector<uint8_t> pubkey(32);
    size_t len = pubkey.size();
    EVP_PKEY_get_raw_public_key(pkey, pubkey.data(), &len);
    pubkey.resize(len);
    return pubkey;
}

} // namespace bitchat 