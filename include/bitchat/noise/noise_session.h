#pragma once

#include "noise_protocol.h"
#include <chrono>
#include <memory>
#include <mutex>
#include <noise/protocol.h>
#include <optional>
#include <string>
#include <vector>

namespace bitchat
{
namespace noise
{

// MARK: - NoiseSession Interface

class NoiseSession
{
public:
    virtual ~NoiseSession() = default;

    // Core encryption/decryption
    virtual std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext) = 0;
    virtual std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext) = 0;

    // Session state
    virtual bool isEstablished() const = 0;
    virtual std::string getPeerID() const = 0;
    virtual std::optional<PublicKey> getRemoteStaticPublicKey() const = 0;
    virtual std::optional<std::vector<uint8_t>> getHandshakeHash() const = 0;

    // Security features
    virtual bool needsRenegotiation() const = 0;
    virtual uint64_t getMessageCount() const = 0;
    virtual std::chrono::system_clock::time_point getLastActivityTime() const = 0;
    virtual bool handshakeInProgress() const = 0;
};

// MARK: - NoiseSessionManager Interface

class NoiseSessionManager
{
public:
    explicit NoiseSessionManager(const PrivateKey &localStaticKey);
    ~NoiseSessionManager() = default;

    // Session management
    std::shared_ptr<NoiseSession> createSession(const std::string &peerID, NoiseRole role);
    std::shared_ptr<NoiseSession> getSession(const std::string &peerID) const;
    void removeSession(const std::string &peerID);
    std::unordered_map<std::string, std::shared_ptr<NoiseSession>> getEstablishedSessions() const;

    // Handshake
    std::vector<uint8_t> initiateHandshake(const std::string &peerID);
    std::optional<std::vector<uint8_t>> handleIncomingHandshake(const std::string &peerID, const std::vector<uint8_t> &message, const std::string &localPeerID);

    // Encryption/Decryption
    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext, const std::string &peerID);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext, const std::string &peerID);

    // Session state
    bool isSessionEstablished(const std::string &peerID) const;
    bool hasEstablishedSession(const std::string &peerID) const;
    std::vector<std::string> getEstablishedSessionIDs() const;

    // Key management
    std::optional<PublicKey> getRemoteStaticKey(const std::string &peerID) const;
    std::optional<std::vector<uint8_t>> getHandshakeHash(const std::string &peerID) const;

    // Session rekeying
    std::vector<std::pair<std::string, bool>> getSessionsNeedingRekey() const;
    void initiateRekey(const std::string &peerID);

    // Callbacks
    void setOnSessionEstablished(std::function<void(const std::string &, const PublicKey &)> callback);
    void setOnSessionFailed(std::function<void(const std::string &, const std::exception &)> callback);

    // Utility methods
    NoiseRole resolveRole(const std::string &localPeerID, const std::string &remotePeerID) const;

private:
    PrivateKey localStaticKey_;
    std::unordered_map<std::string, std::shared_ptr<NoiseSession>> sessions_;
    mutable std::mutex sessionsMutex_;

    // Callbacks
    std::function<void(const std::string &, const PublicKey &)> onSessionEstablished_;
    std::function<void(const std::string &, const std::exception &)> onSessionFailed_;
};

} // namespace noise
} // namespace bitchat
