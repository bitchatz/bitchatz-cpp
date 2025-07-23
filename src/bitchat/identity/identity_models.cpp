#include "bitchat/identity/identity_models.h"
#include "bitchat/noise/noise_protocol.h"
#include <algorithm>
#include <iomanip>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <spdlog/spdlog.h>
#include <sstream>

namespace bitchat
{
namespace identity
{

// MARK: - Identity Model Implementation

nlohmann::json Identity::toJson() const
{
    return {
        {"id", id},
        {"nickname", nickname},
        {"fingerprint", json_utils::arrayToString(fingerprint)},
        {"publicKey", json_utils::arrayToString(publicKey)},
        {"createdAt", json_utils::timePointToString(createdAt)},
        {"lastUsed", json_utils::timePointToString(lastUsed)},
        {"isActive", isActive}};
}

Identity Identity::fromJson(const nlohmann::json &json)
{
    Identity identity;
    identity.id = json["id"];
    identity.nickname = json["nickname"];
    identity.fingerprint = json_utils::arrayFromString(json["fingerprint"]);
    identity.publicKey = json_utils::arrayFromString(json["publicKey"]);
    identity.createdAt = json_utils::timePointFromString(json["createdAt"]);
    identity.lastUsed = json_utils::timePointFromString(json["lastUsed"]);
    identity.isActive = json["isActive"];
    return identity;
}

// MARK: - Identity State Implementation

nlohmann::json IdentityStateInfo::toJson() const
{
    return {
        {"state", static_cast<int>(state)},
        {"errorMessage", errorMessage},
        {"lastUpdate", json_utils::timePointToString(lastUpdate)}};
}

IdentityStateInfo IdentityStateInfo::fromJson(const nlohmann::json &json)
{
    IdentityStateInfo info;
    info.state = static_cast<IdentityState>(json["state"]);
    info.errorMessage = json["errorMessage"];
    info.lastUpdate = json_utils::timePointFromString(json["lastUpdate"]);
    return info;
}

// MARK: - Identity Backup Implementation

nlohmann::json IdentityBackup::toJson() const
{
    nlohmann::json identitiesJson = nlohmann::json::array();
    for (const auto &identity : identities)
    {
        identitiesJson.push_back(identity.toJson());
    }

    return {
        {"version", version},
        {"createdAt", json_utils::timePointToString(createdAt)},
        {"identities", identitiesJson},
        {"checksum", checksum}};
}

IdentityBackup IdentityBackup::fromJson(const nlohmann::json &json)
{
    IdentityBackup backup;
    backup.version = json["version"];
    backup.createdAt = json_utils::timePointFromString(json["createdAt"]);
    backup.checksum = json["checksum"];

    for (const auto &identityJson : json["identities"])
    {
        backup.identities.push_back(Identity::fromJson(identityJson));
    }

    return backup;
}

std::string IdentityBackup::computeChecksum() const
{
    std::string data;
    data += version;
    data += json_utils::timePointToString(createdAt);

    for (const auto &identity : identities)
    {
        data += identity.id;
        data += identity.nickname;
        data += json_utils::arrayToString(identity.fingerprint);
        data += json_utils::arrayToString(identity.publicKey);
    }

    return ::bitchat::identity::computeChecksum(std::vector<uint8_t>(data.begin(), data.end()));
}

bool IdentityBackup::verifyChecksum() const
{
    return checksum == computeChecksum();
}

// MARK: - Identity Recovery Implementation

nlohmann::json IdentityRecoveryData::toJson() const
{
    return {
        {"recoveryPhrase", recoveryPhrase},
        {"recoveryWords", recoveryWords},
        {"salt", salt},
        {"iterations", iterations}};
}

IdentityRecoveryData IdentityRecoveryData::fromJson(const nlohmann::json &json)
{
    IdentityRecoveryData data;
    data.recoveryPhrase = json["recoveryPhrase"];
    data.recoveryWords = json["recoveryWords"];
    data.salt = json["salt"];
    data.iterations = json["iterations"];
    return data;
}

std::string IdentityRecoveryData::generateRecoveryPhrase() const
{
    return recoveryPhrase;
}

std::vector<std::string> IdentityRecoveryData::generateRecoveryWords() const
{
    return recoveryWords;
}

// MARK: - Identity Verification Implementation

nlohmann::json IdentityVerification::toJson() const
{
    return {
        {"identityID", identityID},
        {"verificationCode", verificationCode},
        {"expiresAt", json_utils::timePointToString(expiresAt)},
        {"isVerified", isVerified}};
}

IdentityVerification IdentityVerification::fromJson(const nlohmann::json &json)
{
    IdentityVerification verification;
    verification.identityID = json["identityID"];
    verification.verificationCode = json["verificationCode"];
    verification.expiresAt = json_utils::timePointFromString(json["expiresAt"]);
    verification.isVerified = json["isVerified"];
    return verification;
}

bool IdentityVerification::isExpired() const
{
    return std::chrono::system_clock::now() > expiresAt;
}

// MARK: - Identity Metadata Implementation

nlohmann::json IdentityMetadata::toJson() const
{
    return {
        {"identityID", identityID},
        {"deviceID", deviceID},
        {"appVersion", appVersion},
        {"platform", platform},
        {"lastSync", json_utils::timePointToString(lastSync)},
        {"customFields", customFields}};
}

IdentityMetadata IdentityMetadata::fromJson(const nlohmann::json &json)
{
    IdentityMetadata metadata;
    metadata.identityID = json["identityID"];
    metadata.deviceID = json["deviceID"];
    metadata.appVersion = json["appVersion"];
    metadata.platform = json["platform"];
    metadata.lastSync = json_utils::timePointFromString(json["lastSync"]);
    metadata.customFields = json["customFields"];
    return metadata;
}

// MARK: - Identity Access Control Implementation

nlohmann::json IdentityAccessControl::toJson() const
{
    std::vector<int> permissionsInt;
    for (auto permission : permissions)
    {
        permissionsInt.push_back(static_cast<int>(permission));
    }

    nlohmann::json json = {
        {"identityID", identityID},
        {"permissions", permissionsInt},
        {"grantedAt", json_utils::timePointToString(grantedAt)}};

    if (expiresAt)
    {
        json["expiresAt"] = json_utils::timePointToString(*expiresAt);
    }

    return json;
}

IdentityAccessControl IdentityAccessControl::fromJson(const nlohmann::json &json)
{
    IdentityAccessControl accessControl;
    accessControl.identityID = json["identityID"];

    for (int permissionInt : json["permissions"])
    {
        accessControl.permissions.push_back(static_cast<IdentityPermission>(permissionInt));
    }

    accessControl.grantedAt = json_utils::timePointFromString(json["grantedAt"]);

    if (json.contains("expiresAt") && !json["expiresAt"].is_null())
    {
        accessControl.expiresAt = json_utils::timePointFromString(json["expiresAt"]);
    }

    return accessControl;
}

bool IdentityAccessControl::hasPermission(IdentityPermission permission) const
{
    return std::find(permissions.begin(), permissions.end(), permission) != permissions.end();
}

bool IdentityAccessControl::isExpired() const
{
    if (!expiresAt)
        return false;
    return std::chrono::system_clock::now() > *expiresAt;
}

// MARK: - Identity Event Implementation

nlohmann::json IdentityEvent::toJson() const
{
    return {
        {"type", static_cast<int>(type)},
        {"identityID", identityID},
        {"description", description},
        {"timestamp", json_utils::timePointToString(timestamp)},
        {"metadata", metadata}};
}

IdentityEvent IdentityEvent::fromJson(const nlohmann::json &json)
{
    IdentityEvent event;
    event.type = static_cast<IdentityEventType>(json["type"]);
    event.identityID = json["identityID"];
    event.description = json["description"];
    event.timestamp = json_utils::timePointFromString(json["timestamp"]);
    event.metadata = json["metadata"];
    return event;
}

// MARK: - Utility Functions

std::string generateIdentityID()
{
    std::vector<uint8_t> randomBytes(16);
    if (RAND_bytes(randomBytes.data(), 16) != 1)
    {
        throw std::runtime_error("Failed to generate random bytes for identity ID");
    }

    std::stringstream ss;
    for (uint8_t byte : randomBytes)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

IdentityFingerprint generateFingerprint(const IdentityPublicKey &publicKey)
{
    IdentityFingerprint fingerprint;
    std::vector<uint8_t> keyData(publicKey.begin(), publicKey.end());
    std::vector<uint8_t> hash = noise::sha256(keyData);
    std::copy(hash.begin(), hash.begin() + 32, fingerprint.begin());
    return fingerprint;
}

std::string fingerprintToString(const IdentityFingerprint &fingerprint)
{
    std::stringstream ss;
    for (size_t i = 0; i < fingerprint.size(); ++i)
    {
        if (i > 0 && i % 4 == 0)
            ss << ":";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(fingerprint[i]);
    }
    return ss.str();
}

IdentityFingerprint fingerprintFromString(const std::string &fingerprintStr)
{
    IdentityFingerprint fingerprint;
    std::string cleanStr = fingerprintStr;
    cleanStr.erase(std::remove(cleanStr.begin(), cleanStr.end(), ':'), cleanStr.end());

    if (cleanStr.length() != 64)
    {
        throw std::runtime_error("Invalid fingerprint string length");
    }

    for (size_t i = 0; i < 32; ++i)
    {
        std::string byteStr = cleanStr.substr(i * 2, 2);
        fingerprint[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }

    return fingerprint;
}

std::string generateRecoveryPhrase()
{
    // Generate 12 random words from a predefined list
    // For simplicity, using a small word list. In production, use BIP39 word list
    std::vector<std::string> words = {
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
        "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
        "action", "actor", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult",
        "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree"};

    std::vector<uint8_t> randomBytes(16);
    if (RAND_bytes(randomBytes.data(), 16) != 1)
    {
        throw std::runtime_error("Failed to generate random bytes for recovery phrase");
    }

    std::stringstream ss;
    for (size_t i = 0; i < 12; ++i)
    {
        if (i > 0)
            ss << " ";
        size_t wordIndex = (randomBytes[i % 16] * 256 + randomBytes[(i + 1) % 16]) % words.size();
        ss << words[wordIndex];
    }

    return ss.str();
}

std::vector<std::string> generateRecoveryWords()
{
    std::string phrase = generateRecoveryPhrase();
    std::vector<std::string> words;
    std::stringstream ss(phrase);
    std::string word;

    while (ss >> word)
    {
        words.push_back(word);
    }

    return words;
}

std::string computeChecksum(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> hash = noise::sha256(data);
    std::stringstream ss;
    for (size_t i = 0; i < 8; ++i)
    { // Use first 8 bytes for checksum
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::vector<uint8_t> sha256(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

// MARK: - JSON Serialization Helpers

namespace json_utils
{
std::string timePointToString(const std::chrono::system_clock::time_point &time)
{
    auto time_t = std::chrono::system_clock::to_time_t(time);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  time.time_since_epoch()) %
              1000;

    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count() << "Z";
    return ss.str();
}

std::chrono::system_clock::time_point timePointFromString(const std::string &timeStr)
{
    std::tm tm = {};
    std::stringstream ss(timeStr);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

    auto time_t = std::mktime(&tm);
    return std::chrono::system_clock::from_time_t(time_t);
}

std::string arrayToString(const std::array<uint8_t, 32> &arr)
{
    std::stringstream ss;
    for (uint8_t byte : arr)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::array<uint8_t, 32> arrayFromString(const std::string &str)
{
    std::array<uint8_t, 32> arr{};
    if (str.length() != 64)
    {
        throw std::runtime_error("Invalid array string length");
    }

    for (size_t i = 0; i < 32; ++i)
    {
        std::string byteStr = str.substr(i * 2, 2);
        arr[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
    }

    return arr;
}
} // namespace json_utils

} // namespace identity
} // namespace bitchat
