#include "bitchat/services/noise_service.h"
#include "bitchat/core/constants.h"
#include "bitchat/helpers/noise_helper.h"
#include "bitchat/noise/noise_session_default.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <spdlog/spdlog.h>

namespace bitchat
{

NoiseService::NoiseService()
{
    if (RAND_bytes(localStaticKey.data(), static_cast<int>(localStaticKey.size())) != 1)
    {
        throw std::runtime_error("Failed to generate local static key");
    }
}

NoiseService::~NoiseService()
{
    cleanup();
}

void NoiseService::cleanup()
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    // Clear all sessions
    sessions.clear();

    // Clear OpenSSL
    CRYPTO_set_locking_callback(nullptr);
    CRYPTO_set_id_callback(nullptr);

    ERR_remove_state(0);

    ERR_free_strings();
    EVP_cleanup();

    CRYPTO_cleanup_all_ex_data();
}

std::shared_ptr<NoiseSession> NoiseService::createSession(const std::string &peerID, NoiseRole role)
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    auto session = std::make_shared<NoiseSessionDefault>(peerID, role, localStaticKey);
    sessions[peerID] = session;

    spdlog::info("Created new Noise session for peer: {} with role: {}", peerID, NoiseHelper::noiseRoleToString(role));

    return session;
}

std::shared_ptr<NoiseSession> NoiseService::getSession(const std::string &peerID) const
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    auto it = sessions.find(peerID);
    if (it != sessions.end())
    {
        return it->second;
    }

    return nullptr;
}

void NoiseService::removeSession(const std::string &peerID)
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    auto it = sessions.find(peerID);
    if (it != sessions.end())
    {
        sessions.erase(it);
        spdlog::info("Removed Noise session for peer: {}", peerID);
    }
}

std::unordered_map<std::string, std::shared_ptr<NoiseSession>> NoiseService::getEstablishedSessions() const
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    std::unordered_map<std::string, std::shared_ptr<NoiseSession>> establishedSessions;

    for (const auto &pair : sessions)
    {
        if (pair.second->isSessionEstablished())
        {
            establishedSessions[pair.first] = pair.second;
        }
    }

    return establishedSessions;
}

std::vector<uint8_t> NoiseService::initiateHandshake(const std::string &peerID)
{
    auto session = getSession(peerID);
    if (!session)
    {
        throw std::runtime_error("No session found for peer: " + peerID);
    }

    auto handshakeMessage = session->startHandshake();
    if (!handshakeMessage)
    {
        throw std::runtime_error("Failed to start handshake for peer: " + peerID);
    }

    return *handshakeMessage;
}

std::optional<std::vector<uint8_t>> NoiseService::handleIncomingHandshake(const std::string &peerID, const std::vector<uint8_t> &message, const std::string &localPeerID)
{
    auto session = getSession(peerID);
    if (!session)
    {
        NoiseRole role = resolveRole(localPeerID, peerID);
        session = createSession(peerID, role);
    }

    return session->processHandshakeMessage(message);
}

std::vector<uint8_t> NoiseService::encrypt(const std::vector<uint8_t> &plaintext, const std::string &peerID)
{
    auto session = getSession(peerID);
    if (!session)
    {
        throw std::runtime_error("No session found for peer: " + peerID);
    }

    return session->encrypt(plaintext);
}

std::vector<uint8_t> NoiseService::decrypt(const std::vector<uint8_t> &ciphertext, const std::string &peerID)
{
    auto session = getSession(peerID);
    if (!session)
    {
        throw std::runtime_error("No session found for peer: " + peerID);
    }

    return session->decrypt(ciphertext);
}

bool NoiseService::isSessionEstablished(const std::string &peerID) const
{
    auto session = getSession(peerID);
    return session && session->isSessionEstablished();
}

bool NoiseService::hasEstablishedSession(const std::string &peerID) const
{
    return isSessionEstablished(peerID);
}

std::vector<std::string> NoiseService::getEstablishedSessionIDs() const
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    std::vector<std::string> sessionIDs;

    for (const auto &pair : sessions)
    {
        if (pair.second->isSessionEstablished())
        {
            sessionIDs.push_back(pair.first);
        }
    }

    return sessionIDs;
}

std::optional<NoisePublicKey> NoiseService::getRemoteStaticKey(const std::string &peerID) const
{
    auto session = getSession(peerID);
    if (!session)
    {
        return std::nullopt;
    }

    return session->getRemoteStaticPublicKey();
}

std::optional<std::vector<uint8_t>> NoiseService::getHandshakeHash(const std::string &peerID) const
{
    auto session = getSession(peerID);
    if (!session)
    {
        return std::nullopt;
    }

    return session->getHandshakeHash();
}

std::vector<std::pair<std::string, bool>> NoiseService::getSessionsNeedingRekey() const
{
    std::lock_guard<std::mutex> lock(sessionsMutex);

    std::vector<std::pair<std::string, bool>> sessionsNeedingRekey;

    for (const auto &pair : sessions)
    {
        if (pair.second->isSessionEstablished() && pair.second->needsRenegotiation())
        {
            sessionsNeedingRekey.emplace_back(pair.first, true);
        }
    }

    return sessionsNeedingRekey;
}

void NoiseService::initiateRekey(const std::string &peerID)
{
    auto session = getSession(peerID);
    if (!session)
    {
        throw std::runtime_error("No session found for peer: " + peerID);
    }

    if (!session->isSessionEstablished())
    {
        throw std::runtime_error("Session not established for peer: " + peerID);
    }

    spdlog::info("Initiating rekey for peer: {}", peerID);

    auto handshakeMessage = session->startHandshake();
    if (!handshakeMessage)
    {
        throw std::runtime_error("Failed to start rekey handshake for peer: " + peerID);
    }
}

void NoiseService::setOnSessionEstablished(std::function<void(const std::string &, const NoisePublicKey &)> callback)
{
    onSessionEstablished = callback;
}

void NoiseService::setOnSessionFailed(std::function<void(const std::string &, const std::exception &)> callback)
{
    onSessionFailed = callback;
}

NoiseRole NoiseService::resolveRole(const std::string &localPeerID, const std::string &remotePeerID) const
{
    return localPeerID < remotePeerID ? NoiseRole::Initiator : NoiseRole::Responder;
}

} // namespace bitchat
