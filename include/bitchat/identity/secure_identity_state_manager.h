#pragma once

#include "bitchat/identity/identity_models.h"
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace bitchat
{

// Forward declarations
class CryptoService;

// SecureIdentityStateManager: Manages identity state with encryption
class SecureIdentityStateManager
{
public:
    explicit SecureIdentityStateManager(std::shared_ptr<CryptoService> cryptoService);
    ~SecureIdentityStateManager() = default;

    // Identity management
    bool createIdentity(const std::string &identityID, const std::string &nickname);
    bool deleteIdentity(const std::string &identityID);
    bool activateIdentity(const std::string &identityID);
    bool deactivateIdentity(const std::string &identityID);

    // Identity retrieval
    std::optional<Identity> getIdentity(const std::string &identityID) const;
    std::vector<Identity> getAllIdentities() const;
    std::vector<Identity> getActiveIdentities() const;

    // Identity state
    IdentityState getIdentityState(const std::string &identityID) const;
    IdentityStateInfo getIdentityStateInfo(const std::string &identityID) const;
    void updateIdentityState(const std::string &identityID, IdentityState state, const std::string &errorMessage = "");

    // Backup and recovery
    IdentityBackup createBackup() const;
    bool restoreBackup(const IdentityBackup &backup);
    IdentityRecoveryData createRecoveryData(const std::string &identityID);
    bool restoreFromRecoveryData(const IdentityRecoveryData &recoveryData, const std::string &newIdentityID);

    // Verification
    IdentityVerification createVerification(const std::string &identityID, const std::chrono::system_clock::duration &expiry);
    bool verifyIdentity(const std::string &identityID, const std::string &verificationCode);
    std::optional<IdentityVerification> getVerification(const std::string &identityID) const;

    // Metadata
    void setIdentityMetadata(const std::string &identityID, const IdentityMetadata &metadata);
    std::optional<IdentityMetadata> getIdentityMetadata(const std::string &identityID) const;

    // Access control
    void grantPermission(const std::string &identityID, IdentityPermission permission, const std::optional<std::chrono::system_clock::duration> &expiry = std::nullopt);
    void revokePermission(const std::string &identityID, IdentityPermission permission);
    bool hasPermission(const std::string &identityID, IdentityPermission permission) const;
    std::vector<IdentityPermission> getPermissions(const std::string &identityID) const;

    // Events
    void logEvent(const std::string &identityID, IdentityEventType type, const std::string &description, const std::unordered_map<std::string, std::string> &metadata = {});
    std::vector<IdentityEvent> getEvents(const std::string &identityID, size_t limit = 100) const;
    void clearEvents(const std::string &identityID);

    // Persistence
    bool saveToFile(const std::string &filename) const;
    bool loadFromFile(const std::string &filename);

    // Security
    void setEncryptionKey(const std::vector<uint8_t> &key);
    bool isEncrypted() const;
    void enableEncryption();
    void disableEncryption();

    // Utility
    void cleanup();
    void clearAllData();
    size_t getIdentityCount() const;
    bool hasIdentities() const;

private:
    std::shared_ptr<CryptoService> cryptoService;
    mutable std::mutex dataMutex;

    // Data storage
    std::unordered_map<std::string, Identity> identities;
    std::unordered_map<std::string, IdentityStateInfo> identityStates;
    std::unordered_map<std::string, IdentityBackup> backups;
    std::unordered_map<std::string, IdentityRecoveryData> recoveryData;
    std::unordered_map<std::string, IdentityVerification> verifications;
    std::unordered_map<std::string, IdentityMetadata> metadata;
    std::unordered_map<std::string, IdentityAccessControl> accessControls;
    std::unordered_map<std::string, std::vector<IdentityEvent>> events;

    // Security
    std::vector<uint8_t> encryptionKey;
    bool encryptionEnabled;

    // Private helper methods
    std::vector<uint8_t> encryptData(const std::vector<uint8_t> &data) const;
    std::vector<uint8_t> decryptData(const std::vector<uint8_t> &data) const;
    std::string generateEncryptionKey() const;
    bool validateIdentity(const Identity &identity) const;
    void updateIdentityLastUsed(const std::string &identityID);
    std::vector<uint8_t> computeIdentityHash(const Identity &identity) const;
    bool verifyIdentityHash(const Identity &identity, const std::vector<uint8_t> &hash) const;
    void cleanupExpiredData();
    std::string serializeData() const;
    bool deserializeData(const std::string &data);
    std::vector<uint8_t> signData(const std::vector<uint8_t> &data) const;
    bool verifySignature(const std::vector<uint8_t> &data, const std::vector<uint8_t> &signature) const;
    void logSecurityEvent(const std::string &identityID, const std::string &event, const std::string &details = "");
    bool isIdentityExpired(const Identity &identity) const;
    void rotateEncryptionKey();
    std::vector<uint8_t> deriveKey(const std::string &salt, const std::vector<uint8_t> &masterKey) const;
    void secureErase(std::vector<uint8_t> &data);
    bool validateBackupIntegrity(const IdentityBackup &backup) const;
    void updateBackupChecksum(IdentityBackup &backup) const;
    std::string generateSecureRandomString(size_t length) const;
    bool validateRecoveryData(const IdentityRecoveryData &recoveryData) const;
    void updateRecoveryIterations(IdentityRecoveryData &recoveryData);
    bool validateVerificationCode(const std::string &code) const;
    void cleanupExpiredVerifications();
    bool validateMetadata(const IdentityMetadata &metadata) const;
    void updateMetadataLastSync(IdentityMetadata &metadata);
    bool validateAccessControl(const IdentityAccessControl &accessControl) const;
    void cleanupExpiredPermissions();
    bool validateEvent(const IdentityEvent &event) const;
    void limitEventHistory(const std::string &identityID, size_t maxEvents);
    std::vector<uint8_t> hashPassword(const std::string &password, const std::vector<uint8_t> &salt) const;
    bool verifyPassword(const std::string &password, const std::vector<uint8_t> &hash, const std::vector<uint8_t> &salt) const;
    void updatePasswordHash(const std::string &identityID, const std::string &newPassword);
    bool validatePasswordStrength(const std::string &password) const;
    void generatePasswordSuggestions(const std::string &identityID, std::vector<std::string> &suggestions);
    std::string generateMnemonicPhrase(const std::vector<uint8_t> &entropy) const;
    std::vector<uint8_t> deriveEntropyFromMnemonic(const std::string &mnemonic) const;
    bool validateMnemonicPhrase(const std::string &mnemonic) const;
    void backupToCloud(const IdentityBackup &backup, const std::string &cloudProvider);
    bool restoreFromCloud(const std::string &cloudProvider, const std::string &backupID);
    void syncWithCloud(const std::string &identityID);
    bool validateCloudBackup(const IdentityBackup &backup, const std::string &cloudProvider) const;
    void updateCloudSyncStatus(const std::string &identityID, bool synced);
    std::vector<std::string> getCloudBackupList(const std::string &cloudProvider) const;
    void encryptBackupForCloud(IdentityBackup &backup, const std::string &cloudProvider) const;
    void decryptBackupFromCloud(IdentityBackup &backup, const std::string &cloudProvider) const;
    bool validateCloudCredentials(const std::string &cloudProvider) const;
    void updateCloudCredentials(const std::string &cloudProvider, const std::string &credentials);
    std::string generateCloudBackupID() const;
    void cleanupCloudBackups(const std::string &cloudProvider, size_t maxBackups);
    bool validateBackupVersion(const IdentityBackup &backup) const;
    void migrateBackupVersion(IdentityBackup &backup);
    std::vector<std::string> getSupportedBackupVersions() const;
    bool validateBackupCompatibility(const IdentityBackup &backup) const;
    void updateBackupCompatibility(IdentityBackup &backup);
    std::string generateBackupChecksum(const IdentityBackup &backup) const;
    bool verifyBackupChecksum(const IdentityBackup &backup) const;
    void updateBackupTimestamp(IdentityBackup &backup);
    bool validateBackupSize(const IdentityBackup &backup) const;
    void compressBackup(IdentityBackup &backup) const;
    void decompressBackup(IdentityBackup &backup) const;
    bool validateBackupCompression(const IdentityBackup &backup) const;
    void updateBackupCompression(IdentityBackup &backup);
    std::string generateBackupFilename(const IdentityBackup &backup) const;
    bool validateBackupFilename(const std::string &filename) const;
    void updateBackupFilename(IdentityBackup &backup, const std::string &filename);
    std::vector<std::string> getBackupFileList(const std::string &directory) const;
    void cleanupBackupFiles(const std::string &directory, size_t maxFiles);
    bool validateBackupDirectory(const std::string &directory) const;
    void createBackupDirectory(const std::string &directory);
    void updateBackupDirectory(IdentityBackup &backup, const std::string &directory);
    std::string generateBackupPath(const IdentityBackup &backup, const std::string &directory) const;
    bool validateBackupPath(const std::string &path) const;
    void updateBackupPath(IdentityBackup &backup, const std::string &path);
    std::vector<std::string> getBackupPathList(const std::string &basePath) const;
    void cleanupBackupPaths(const std::string &basePath, size_t maxPaths);
    bool validateBackupBasePath(const std::string &basePath) const;
    void createBackupBasePath(const std::string &basePath);
    void updateBackupBasePath(IdentityBackup &backup, const std::string &basePath);
    std::string generateBackupFullPath(const IdentityBackup &backup, const std::string &basePath) const;
    bool validateBackupFullPath(const std::string &fullPath) const;
    void updateBackupFullPath(IdentityBackup &backup, const std::string &fullPath);
    std::vector<std::string> getBackupFullPathList(const std::string &basePath) const;
    void cleanupBackupFullPaths(const std::string &basePath, size_t maxPaths);
    bool validateBackupFullBasePath(const std::string &basePath) const;
    void createBackupFullBasePath(const std::string &basePath);
    void updateBackupFullBasePath(IdentityBackup &backup, const std::string &basePath);
};

} // namespace bitchat
