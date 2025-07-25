#include "bitchat/noise/noise_session_default.h"
#include "bitchat/core/constants.h"
#include <spdlog/spdlog.h>

namespace bitchat
{

NoiseSessionDefault::NoiseSessionDefault(const std::string &peerID, NoiseRole role, const NoisePrivateKey &localStaticKey)
    : peerID(peerID)
    , role(role)
    , localStaticKey(localStaticKey)
    , sessionEstablished(false)
    , messageCount(0)
    , lastActivityTime(std::chrono::system_clock::now())
    , creationTime(std::chrono::system_clock::now())
{
}

std::vector<uint8_t> NoiseSessionDefault::encrypt(const std::vector<uint8_t> &plaintext)
{
    if (!sessionEstablished)
    {
        throw std::runtime_error("Session not established");
    }

    messageCount++;
    lastActivityTime = std::chrono::system_clock::now();
    return plaintext;
}

std::vector<uint8_t> NoiseSessionDefault::decrypt(const std::vector<uint8_t> &ciphertext)
{
    if (!sessionEstablished)
    {
        throw std::runtime_error("Session not established");
    }

    messageCount++;
    lastActivityTime = std::chrono::system_clock::now();
    return ciphertext;
}

bool NoiseSessionDefault::isSessionEstablished() const
{
    return sessionEstablished;
}

std::string NoiseSessionDefault::getPeerID() const
{
    return peerID;
}

std::optional<NoisePublicKey> NoiseSessionDefault::getRemoteStaticPublicKey() const
{
    return remoteStaticKey;
}

std::optional<std::vector<uint8_t>> NoiseSessionDefault::getHandshakeHash() const
{
    return handshakeHash;
}

std::optional<std::vector<uint8_t>> NoiseSessionDefault::startHandshake()
{
    if (sessionEstablished)
    {
        throw std::runtime_error("Session already established");
    }

    sessionEstablished = true;
    handshakeHash = std::vector<uint8_t>(32, 0);

    spdlog::info("Simple handshake completed for peer: {} (role: {})", peerID,
                 role == NoiseRole::Initiator ? "Initiator" : "Responder");

    std::vector<uint8_t> handshakeMsg = {0x01, 0x02, 0x03};
    handshakeMsg.insert(handshakeMsg.end(), localStaticKey.begin(), localStaticKey.begin() + 3);

    return handshakeMsg;
}

bool NoiseSessionDefault::needsRenegotiation() const
{
    auto now = std::chrono::system_clock::now();
    auto timeSinceCreation = now - creationTime;

    if (timeSinceCreation > constants::NOISE_SESSION_TIMEOUT)
    {
        return true;
    }

    uint64_t messageThreshold = static_cast<uint64_t>(constants::NOISE_MAX_MESSAGES_PER_SESSION * 0.9);
    if (messageCount >= messageThreshold)
    {
        return true;
    }

    return false;
}

uint64_t NoiseSessionDefault::getMessageCount() const
{
    return messageCount;
}

std::chrono::system_clock::time_point NoiseSessionDefault::getLastActivityTime() const
{
    return lastActivityTime;
}

bool NoiseSessionDefault::handshakeInProgress() const
{
    return !sessionEstablished;
}

std::optional<std::vector<uint8_t>> NoiseSessionDefault::processHandshakeMessage([[maybe_unused]] const std::vector<uint8_t> &message)
{
    if (sessionEstablished)
    {
        throw std::runtime_error("Session already established");
    }

    sessionEstablished = true;
    handshakeHash = std::vector<uint8_t>(32, 0);

    spdlog::info("Simple handshake processed for peer: {} (role: {})", peerID,
                 role == NoiseRole::Initiator ? "Initiator" : "Responder");

    std::vector<uint8_t> response = {0x04, 0x05, 0x06};
    response.insert(response.end(), localStaticKey.begin() + 3, localStaticKey.begin() + 6);

    return response;
}

} // namespace bitchat
