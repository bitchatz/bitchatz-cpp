#include "bitchat/services/identity_service.h"
#include "bitchat/services/crypto_service.h"
#include <fstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>
#include <sstream>

namespace bitchat
{

IdentityService &IdentityService::getInstance()
{
    static IdentityService instance;
    return instance;
}

// MARK: - Identity Resolution

IdentityHint IdentityService::resolveIdentity(const std::string &peerID [[maybe_unused]], const std::string &claimedNickname)
{
    std::lock_guard<std::mutex> lock(mutex);

    // Check if we have candidates based on nickname
    auto it = cache.nicknameIndex.find(claimedNickname);
    if (it != cache.nicknameIndex.end())
    {
        const auto &fingerprints = it->second;
        if (fingerprints.size() == 1)
        {
            return IdentityHint::LIKELY_KNOWN;
        }
        else
        {
            return IdentityHint::AMBIGUOUS;
        }
    }

    return IdentityHint::UNKNOWN;
}

// MARK: - Social Identity Management

std::shared_ptr<SocialIdentity> IdentityService::getSocialIdentity(const std::string &fingerprint)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto it = cache.socialIdentities.find(fingerprint);
    if (it != cache.socialIdentities.end())
    {
        return std::make_shared<SocialIdentity>(it->second);
    }

    return nullptr;
}

std::vector<SocialIdentity> IdentityService::getAllSocialIdentities()
{
    std::lock_guard<std::mutex> lock(mutex);

    std::vector<SocialIdentity> identities;
    identities.reserve(cache.socialIdentities.size());

    for (const auto &pair : cache.socialIdentities)
    {
        identities.push_back(pair.second);
    }

    return identities;
}

void IdentityService::updateSocialIdentity(const SocialIdentity &identity)
{
    std::lock_guard<std::mutex> lock(mutex);

    // Update social identity
    cache.socialIdentities[identity.fingerprint] = identity;

    // Update nickname index
    auto existingIt = cache.socialIdentities.find(identity.fingerprint);
    if (existingIt != cache.socialIdentities.end())
    {
        // Remove old nickname from index if changed
        const std::string &oldNickname = existingIt->second.claimedNickname;
        if (oldNickname != identity.claimedNickname)
        {
            auto indexIt = cache.nicknameIndex.find(oldNickname);
            if (indexIt != cache.nicknameIndex.end())
            {
                auto &fingerprints = indexIt->second;
                fingerprints.erase(std::remove(fingerprints.begin(), fingerprints.end(), identity.fingerprint), fingerprints.end());

                if (fingerprints.empty())
                {
                    cache.nicknameIndex.erase(indexIt);
                }
            }
        }
    }

    // Add new nickname to index
    cache.nicknameIndex[identity.claimedNickname].push_back(identity.fingerprint);

    // Save to persistent storage
    saveIdentityCache();
}

// MARK: - Favorites Management

std::vector<std::string> IdentityService::getFavorites()
{
    std::lock_guard<std::mutex> lock(mutex);

    std::vector<std::string> favorites;
    for (const auto &pair : cache.socialIdentities)
    {
        if (pair.second.isFavorite)
        {
            favorites.push_back(pair.first);
        }
    }

    return favorites;
}

void IdentityService::setFavorite(const std::string &fingerprint, bool isFavorite)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto it = cache.socialIdentities.find(fingerprint);
    if (it != cache.socialIdentities.end())
    {
        it->second.isFavorite = isFavorite;
    }
    else
    {
        // Create new social identity for this fingerprint
        SocialIdentity newIdentity;
        newIdentity.fingerprint = fingerprint;
        newIdentity.localPetname = "";
        newIdentity.claimedNickname = "Unknown";
        newIdentity.trustLevel = TrustLevel::UNKNOWN;
        newIdentity.isFavorite = isFavorite;
        newIdentity.isBlocked = false;
        newIdentity.notes = "";

        cache.socialIdentities[fingerprint] = newIdentity;
    }

    saveIdentityCache();
}

bool IdentityService::isFavorite(const std::string &fingerprint)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto it = cache.socialIdentities.find(fingerprint);
    return (it != cache.socialIdentities.end()) ? it->second.isFavorite : false;
}

// MARK: - Blocked Users Management

bool IdentityService::isBlocked(const std::string &fingerprint)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto it = cache.socialIdentities.find(fingerprint);
    return (it != cache.socialIdentities.end()) ? it->second.isBlocked : false;
}

void IdentityService::setBlocked(const std::string &fingerprint, bool isBlocked)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto it = cache.socialIdentities.find(fingerprint);
    if (it != cache.socialIdentities.end())
    {
        it->second.isBlocked = isBlocked;
        if (isBlocked)
        {
            it->second.isFavorite = false; // Can't be both favorite and blocked
        }
    }
    else
    {
        // Create new social identity for this fingerprint
        SocialIdentity newIdentity;
        newIdentity.fingerprint = fingerprint;
        newIdentity.localPetname = "";
        newIdentity.claimedNickname = "Unknown";
        newIdentity.trustLevel = TrustLevel::UNKNOWN;
        newIdentity.isFavorite = false;
        newIdentity.isBlocked = isBlocked;
        newIdentity.notes = "";

        cache.socialIdentities[fingerprint] = newIdentity;
    }

    saveIdentityCache();
}

// MARK: - Ephemeral Session Management

void IdentityService::registerEphemeralSession(const std::string &peerID, HandshakeState handshakeState)
{
    std::lock_guard<std::mutex> lock(mutex);

    EphemeralIdentity identity;
    identity.peerID = peerID;
    identity.sessionStart = std::chrono::system_clock::now();
    identity.handshakeState = handshakeState;

    ephemeralSessions[peerID] = identity;
}

void IdentityService::updateHandshakeState(const std::string &peerID, HandshakeState state, const std::string &fingerprint, const std::string &failureReason)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto it = ephemeralSessions.find(peerID);
    if (it != ephemeralSessions.end())
    {
        it->second.handshakeState = state;

        if (state == HandshakeState::COMPLETED)
        {
            it->second.fingerprint = fingerprint;
            cache.lastInteractions[fingerprint] = std::chrono::system_clock::now();
            saveIdentityCache();
        }
        else if (state == HandshakeState::FAILED)
        {
            it->second.failureReason = failureReason;
        }
    }
}

HandshakeState IdentityService::getHandshakeState(const std::string &peerID)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto it = ephemeralSessions.find(peerID);
    return (it != ephemeralSessions.end()) ? it->second.handshakeState : HandshakeState::NONE;
}

// MARK: - Pending Actions

void IdentityService::setPendingAction(const std::string &peerID, const PendingActions &action)
{
    std::lock_guard<std::mutex> lock(mutex);
    pendingActions[peerID] = action;
}

void IdentityService::applyPendingActions(const std::string &peerID, const std::string &fingerprint)
{
    std::lock_guard<std::mutex> lock(mutex);

    auto it = pendingActions.find(peerID);
    if (it == pendingActions.end())
    {
        return;
    }

    const auto &actions = it->second;

    // Get or create social identity
    auto identityIt = cache.socialIdentities.find(fingerprint);
    SocialIdentity identity;

    if (identityIt != cache.socialIdentities.end())
    {
        identity = identityIt->second;
    }
    else
    {
        identity.fingerprint = fingerprint;
        identity.localPetname = "";
        identity.claimedNickname = "Unknown";
        identity.trustLevel = TrustLevel::UNKNOWN;
        identity.isFavorite = false;
        identity.isBlocked = false;
        identity.notes = "";
    }

    // Apply pending actions
    if (actions.toggleFavorite.has_value())
    {
        identity.isFavorite = actions.toggleFavorite.value();
    }
    if (actions.setTrustLevel != TrustLevel::UNKNOWN)
    {
        identity.trustLevel = actions.setTrustLevel;
    }
    if (!actions.setPetname.empty())
    {
        identity.localPetname = actions.setPetname;
    }

    // Save updated identity
    cache.socialIdentities[fingerprint] = identity;
    pendingActions.erase(it);
    saveIdentityCache();
}

// MARK: - Verification

void IdentityService::setVerified(const std::string &fingerprint, bool verified)
{
    std::lock_guard<std::mutex> lock(mutex);

    if (verified)
    {
        if (std::find(cache.verifiedFingerprints.begin(), cache.verifiedFingerprints.end(), fingerprint) == cache.verifiedFingerprints.end())
        {
            cache.verifiedFingerprints.push_back(fingerprint);
        }
    }
    else
    {
        cache.verifiedFingerprints.erase(
            std::remove(cache.verifiedFingerprints.begin(), cache.verifiedFingerprints.end(), fingerprint),
            cache.verifiedFingerprints.end());
    }

    // Update trust level if social identity exists
    auto it = cache.socialIdentities.find(fingerprint);
    if (it != cache.socialIdentities.end())
    {
        it->second.trustLevel = verified ? TrustLevel::VERIFIED : TrustLevel::CASUAL;
    }

    saveIdentityCache();
}

bool IdentityService::isVerified(const std::string &fingerprint)
{
    std::lock_guard<std::mutex> lock(mutex);

    return std::find(cache.verifiedFingerprints.begin(), cache.verifiedFingerprints.end(), fingerprint) != cache.verifiedFingerprints.end();
}

// MARK: - Cleanup

void IdentityService::clearAllIdentityData()
{
    std::lock_guard<std::mutex> lock(mutex);

    cache = IdentityCache();
    ephemeralSessions.clear();
    cryptographicIdentities.clear();
    pendingActions.clear();

    // TODO: Delete from persistent storage
}

void IdentityService::removeEphemeralSession(const std::string &peerID)
{
    std::lock_guard<std::mutex> lock(mutex);
    ephemeralSessions.erase(peerID);
    pendingActions.erase(peerID);
}

// MARK: - Persistence

bool IdentityService::loadIdentityCache()
{
    // TODO: Implement loading from encrypted storage
    // For now, start with empty cache
    return true;
}

bool IdentityService::saveIdentityCache()
{
    // TODO: Implement saving to encrypted storage
    // For now, just return success
    return true;
}

// MARK: - Helper Methods

std::string IdentityService::generateFingerprint(const std::vector<uint8_t> &publicKey)
{
    // Use modern OpenSSL EVP interface instead of deprecated SHA256_* functions
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return "";
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    if (EVP_DigestUpdate(ctx, publicKey.data(), publicKey.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    EVP_MD_CTX_free(ctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hashLen; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

std::vector<uint8_t> IdentityService::encryptCache(const IdentityCache &cache [[maybe_unused]])
{
    // TODO: Implement encryption using CryptoService
    // For now, return empty vector
    return std::vector<uint8_t>();
}

IdentityCache IdentityService::decryptCache(const std::vector<uint8_t> &encryptedData [[maybe_unused]])
{
    // TODO: Implement decryption using CryptoService
    // For now, return empty cache
    return IdentityCache();
}

} // namespace bitchat
