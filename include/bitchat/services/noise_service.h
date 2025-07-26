#pragma once

#include "bitchat/noise/noise_protocol.h"
#include "bitchat/noise/noise_role.h"
#include "bitchat/noise/noise_security_error.h"
#include "bitchat/noise/noise_session.h"
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace bitchat
{

// NoiseSession Interface is now defined in noise/noise_session.h

// NoiseService Interface

class NoiseService
{
public:
    NoiseService();
    ~NoiseService() = default;

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
    std::optional<NoisePublicKey> getRemoteStaticKey(const std::string &peerID) const;
    std::optional<std::vector<uint8_t>> getHandshakeHash(const std::string &peerID) const;

    // Session rekeying
    std::vector<std::pair<std::string, bool>> getSessionsNeedingRekey() const;
    void initiateRekey(const std::string &peerID);

    // Callbacks
    void setOnSessionEstablished(std::function<void(const std::string &, const NoisePublicKey &)> callback);
    void setOnSessionFailed(std::function<void(const std::string &, const std::exception &)> callback);

    // Utility methods
    NoiseRole resolveRole(const std::string &localPeerID, const std::string &remotePeerID) const;

private:
    NoisePrivateKey localStaticKey;
    std::unordered_map<std::string, std::shared_ptr<NoiseSession>> sessions;
    mutable std::mutex sessionsMutex;

    // Callbacks
    std::function<void(const std::string &, const NoisePublicKey &)> onSessionEstablished;
    std::function<void(const std::string &, const std::exception &)> onSessionFailed;
};

} // namespace bitchat
