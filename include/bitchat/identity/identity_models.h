#pragma once

#include <array>
#include <chrono>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace bitchat
{

// Identity Types

using IdentityFingerprint = std::array<uint8_t, 32>;
using IdentityPublicKey = std::array<uint8_t, 32>;
using IdentityPrivateKey = std::array<uint8_t, 32>;

// Identity Model

struct Identity
{
    std::string id;
    std::string nickname;
    IdentityFingerprint fingerprint;
    IdentityPublicKey publicKey;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastUsed;
    bool isActive;

    // Serialization
    nlohmann::json toJson() const;
    static Identity fromJson(const nlohmann::json &json);
};

// Identity State

enum class IdentityState
{
    Uninitialized,
    Creating,
    Active,
    Inactive,
    Error
};

struct IdentityStateInfo
{
    IdentityState state;
    std::string errorMessage;
    std::chrono::system_clock::time_point lastUpdate;

    nlohmann::json toJson() const;
    static IdentityStateInfo fromJson(const nlohmann::json &json);
};

// Identity Backup

struct IdentityBackup
{
    std::string version;
    std::chrono::system_clock::time_point createdAt;
    std::vector<Identity> identities;
    std::string checksum;

    nlohmann::json toJson() const;
    static IdentityBackup fromJson(const nlohmann::json &json);
    std::string computeChecksum() const;
    bool verifyChecksum() const;
};

// Identity Recovery

struct IdentityRecoveryData
{
    std::string recoveryPhrase;
    std::vector<std::string> recoveryWords;
    std::string salt;
    int iterations;

    nlohmann::json toJson() const;
    static IdentityRecoveryData fromJson(const nlohmann::json &json);
    std::string generateRecoveryPhrase() const;
    std::vector<std::string> generateRecoveryWords() const;
};

// Identity Verification

struct IdentityVerification
{
    std::string identityID;
    std::string verificationCode;
    std::chrono::system_clock::time_point expiresAt;
    bool isVerified;

    nlohmann::json toJson() const;
    static IdentityVerification fromJson(const nlohmann::json &json);
    bool isExpired() const;
};

// Identity Metadata

struct IdentityMetadata
{
    std::string identityID;
    std::string deviceID;
    std::string appVersion;
    std::string platform;
    std::chrono::system_clock::time_point lastSync;
    std::unordered_map<std::string, std::string> customFields;

    nlohmann::json toJson() const;
    static IdentityMetadata fromJson(const nlohmann::json &json);
};

// Identity Permissions

enum class IdentityPermission
{
    Read,
    Write,
    Delete,
    Share,
    Backup,
    Restore
};

struct IdentityAccessControl
{
    std::string identityID;
    std::vector<IdentityPermission> permissions;
    std::chrono::system_clock::time_point grantedAt;
    std::optional<std::chrono::system_clock::time_point> expiresAt;

    nlohmann::json toJson() const;
    static IdentityAccessControl fromJson(const nlohmann::json &json);
    bool hasPermission(IdentityPermission permission) const;
    bool isExpired() const;
};

// Identity Events

enum class IdentityEventType
{
    Created,
    Updated,
    Deleted,
    Activated,
    Deactivated,
    BackupCreated,
    BackupRestored,
    RecoveryInitiated,
    RecoveryCompleted,
    VerificationRequested,
    VerificationCompleted
};

struct IdentityEvent
{
    IdentityEventType type;
    std::string identityID;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
    std::unordered_map<std::string, std::string> metadata;

    nlohmann::json toJson() const;
    static IdentityEvent fromJson(const nlohmann::json &json);
};

// Utility Functions

std::string generateIdentityID();
IdentityFingerprint generateFingerprint(const IdentityPublicKey &publicKey);
std::string fingerprintToString(const IdentityFingerprint &fingerprint);
IdentityFingerprint fingerprintFromString(const std::string &fingerprintStr);
std::string generateRecoveryPhrase();
std::vector<std::string> generateRecoveryWords();
std::string computeChecksum(const std::vector<uint8_t> &data);
std::vector<uint8_t> sha256(const std::vector<uint8_t> &data);

// Identity Data Class
class IdentityData
{
public:
    IdentityData();
    std::string generatePeerID();
    std::vector<uint8_t> generateIdentityHash(const std::string &peerID, const std::string &channelName);
};

// JSON Serialization Helpers

namespace json_utils
{
std::string timePointToString(const std::chrono::system_clock::time_point &time);
std::chrono::system_clock::time_point timePointFromString(const std::string &timeStr);
std::string arrayToString(const std::array<uint8_t, 32> &arr);
std::array<uint8_t, 32> arrayFromString(const std::string &str);
} // namespace json_utils

} // namespace bitchat
