#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace bitchat
{

// Identity Models

enum class TrustLevel
{
    UNKNOWN,
    CASUAL,
    TRUSTED,
    VERIFIED
};

enum class HandshakeState
{
    NONE,
    INITIATED,
    IN_PROGRESS,
    COMPLETED,
    FAILED
};

struct EphemeralIdentity
{
    std::string peerID;
    std::chrono::system_clock::time_point sessionStart;
    HandshakeState handshakeState;
    std::string fingerprint;   // Only set when handshake completed
    std::string failureReason; // Only set when handshake failed
};

struct CryptographicIdentity
{
    std::string fingerprint;
    std::vector<uint8_t> publicKey;
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastHandshake;
};

struct SocialIdentity
{
    std::string fingerprint;
    std::string localPetname;
    std::string claimedNickname;
    TrustLevel trustLevel;
    bool isFavorite;
    bool isBlocked;
    std::string notes;
};

struct IdentityCache
{
    std::unordered_map<std::string, SocialIdentity> socialIdentities;
    std::unordered_map<std::string, std::vector<std::string>> nicknameIndex; // nickname -> [fingerprints]
    std::vector<std::string> verifiedFingerprints;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> lastInteractions;
    int version = 1;
};

enum class IdentityHint
{
    UNKNOWN,
    LIKELY_KNOWN,
    AMBIGUOUS,
    VERIFIED
};

struct PendingActions
{
    std::optional<bool> toggleFavorite;
    TrustLevel setTrustLevel = TrustLevel::UNKNOWN;
    std::string setPetname;
};

struct PrivacySettings
{
    bool persistIdentityCache = false;
    bool showLastSeen = false;
    bool autoAcceptKnownFingerprints = false;
    bool rememberNicknameHistory = false;
    bool shareTrustNetworkHints = false;
};

// Identity Service

class IdentityService
{
public:
    static IdentityService &getInstance();

    // Identity Resolution
    IdentityHint resolveIdentity(const std::string &peerID, const std::string &claimedNickname);

    // Social Identity Management
    std::shared_ptr<SocialIdentity> getSocialIdentity(const std::string &fingerprint);
    std::vector<SocialIdentity> getAllSocialIdentities();
    void updateSocialIdentity(const SocialIdentity &identity);

    // Favorites Management
    std::vector<std::string> getFavorites();
    void setFavorite(const std::string &fingerprint, bool isFavorite);
    bool isFavorite(const std::string &fingerprint);

    // Blocked Users Management
    bool isBlocked(const std::string &fingerprint);
    void setBlocked(const std::string &fingerprint, bool isBlocked);

    // Ephemeral Session Management
    void registerEphemeralSession(const std::string &peerID, HandshakeState handshakeState = HandshakeState::NONE);
    void updateHandshakeState(const std::string &peerID, HandshakeState state, const std::string &fingerprint = "", const std::string &failureReason = "");
    HandshakeState getHandshakeState(const std::string &peerID);

    // Pending Actions
    void setPendingAction(const std::string &peerID, const PendingActions &action);
    void applyPendingActions(const std::string &peerID, const std::string &fingerprint);

    // Verification
    void setVerified(const std::string &fingerprint, bool verified);
    bool isVerified(const std::string &fingerprint);

    // Cleanup
    void clearAllIdentityData();
    void removeEphemeralSession(const std::string &peerID);

    // Persistence
    bool loadIdentityCache();
    bool saveIdentityCache();

private:
    IdentityService() = default;
    ~IdentityService() = default;
    IdentityService(const IdentityService &) = delete;
    IdentityService &operator=(const IdentityService &) = delete;

    // In-memory state
    std::unordered_map<std::string, EphemeralIdentity> ephemeralSessions;
    std::unordered_map<std::string, CryptographicIdentity> cryptographicIdentities;
    IdentityCache cache;
    std::unordered_map<std::string, PendingActions> pendingActions;

    // Thread safety
    std::mutex mutex;

    // Privacy settings
    PrivacySettings privacySettings;

    // Helper methods
    std::string generateFingerprint(const std::vector<uint8_t> &publicKey);
    std::vector<uint8_t> encryptCache(const IdentityCache &cache);
    IdentityCache decryptCache(const std::vector<uint8_t> &encryptedData);
};

} // namespace bitchat
