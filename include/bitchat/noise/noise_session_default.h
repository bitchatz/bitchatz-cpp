#pragma once

#include "bitchat/core/constants.h"
#include "bitchat/noise/noise_role.h"
#include "bitchat/noise/noise_session.h"
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace bitchat
{

class NoiseSessionDefault : public NoiseSession
{
public:
    NoiseSessionDefault(const std::string &peerID, NoiseRole role, const NoisePrivateKey &localStaticKey);
    ~NoiseSessionDefault() override = default;

    std::vector<uint8_t> encrypt(const std::vector<uint8_t> &plaintext) override;
    std::vector<uint8_t> decrypt(const std::vector<uint8_t> &ciphertext) override;
    bool isSessionEstablished() const override;
    std::string getPeerID() const override;
    std::optional<NoisePublicKey> getRemoteStaticPublicKey() const override;
    std::optional<std::vector<uint8_t>> getHandshakeHash() const override;
    std::optional<std::vector<uint8_t>> startHandshake() override;
    bool needsRenegotiation() const override;
    uint64_t getMessageCount() const override;
    std::chrono::system_clock::time_point getLastActivityTime() const override;
    bool handshakeInProgress() const override;
    std::optional<std::vector<uint8_t>> processHandshakeMessage([[maybe_unused]] const std::vector<uint8_t> &message) override;

private:
    std::string peerID;
    NoiseRole role;
    NoisePrivateKey localStaticKey;
    std::optional<NoisePublicKey> remoteStaticKey;
    std::optional<std::vector<uint8_t>> handshakeHash;
    bool sessionEstablished;
    uint64_t messageCount;
    std::chrono::system_clock::time_point lastActivityTime;
    std::chrono::system_clock::time_point creationTime;
    mutable std::mutex sessionMutex;
};

} // namespace bitchat
