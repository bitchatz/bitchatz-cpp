#pragma once

#include "bitchat/identity/identity_models.h"
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace bitchat
{
namespace identity
{

// Secure Identity State Manager

class SecureIdentityStateManager
{
private:
    // Current identity
    std::optional<Identity> currentIdentity_;
    IdentityStateInfo stateInfo_;

    // All identities
    std::unordered_map<std::string, Identity> identities_;

    // Recovery data
    std::optional<IdentityRecoveryData> recoveryData_;

    // Verification data
    std::unordered_map<std::string, IdentityVerification> verifications_;

    // Metadata
    std::unordered_map<std::string, IdentityMetadata> metadata_;

    // Access control
    std::unordered_map<std::string, IdentityAccessControl> accessControls_;

    // Events
    std::vector<IdentityEvent> events_;

    // Thread safety
    mutable std::shared_mutex stateMutex_;

    // File paths
    std::filesystem::path dataDirectory_;
    std::filesystem::path identitiesFile_;
    std::filesystem::path stateFile_;
    std::filesystem::path recoveryFile_;
    std::filesystem::path verificationsFile_;
    std::filesystem::path metadataFile_;
    std::filesystem::path accessControlsFile_;
    std::filesystem::path eventsFile_;

    // Callbacks
    std::function<void(const Identity &)> onIdentityCreated_;
    std::function<void(const Identity &)> onIdentityUpdated_;
    std::function<void(const std::string &)> onIdentityDeleted_;
    std::function<void(IdentityState)> onStateChanged_;
    std::function<void(const IdentityEvent &)> onEventOccurred_;

public:
    explicit SecureIdentityStateManager(const std::string &dataDirectory = "data");
    ~SecureIdentityStateManager();

    // Initialization

    bool initialize();
    bool loadFromStorage();
    bool saveToStorage();

    // Identity Management

    /// Create a new identity
    std::optional<Identity> createIdentity(const std::string &nickname);

    /// Get current identity
    std::optional<Identity> getCurrentIdentity() const;

    /// Set current identity
    bool setCurrentIdentity(const std::string &identityId);

    /// Get all identities
    std::vector<Identity> getAllIdentities() const;

    /// Get identity by ID
    std::optional<Identity> getIdentity(const std::string &identityId) const;

    /// Update identity
    bool updateIdentity(const Identity &identity);

    /// Delete identity
    bool deleteIdentity(const std::string &identityId);

    /// Activate identity
    bool activateIdentity(const std::string &identityId);

    /// Deactivate identity
    bool deactivateIdentity(const std::string &identityId);

    // State Management

    /// Get current state
    IdentityStateInfo getStateInfo() const;

    /// Update state
    void updateState(IdentityState state, const std::string &errorMessage = "");

    /// Check if initialized
    bool isInitialized() const;

    // Recovery Management

    /// Generate recovery data
    std::optional<IdentityRecoveryData> generateRecoveryData();

    /// Get recovery data
    std::optional<IdentityRecoveryData> getRecoveryData() const;

    /// Restore from recovery phrase
    bool restoreFromRecoveryPhrase(const std::string &recoveryPhrase);

    /// Validate recovery phrase
    bool validateRecoveryPhrase(const std::string &recoveryPhrase);

    // Verification Management

    /// Request verification
    std::optional<IdentityVerification> requestVerification(const std::string &identityId);

    /// Complete verification
    bool completeVerification(const std::string &identityId, const std::string &code);

    /// Get verification status
    std::optional<IdentityVerification> getVerification(const std::string &identityId) const;

    /// Check if verified
    bool isVerified(const std::string &identityId) const;

    // Metadata Management

    /// Set metadata
    bool setMetadata(const IdentityMetadata &metadata);

    /// Get metadata
    std::optional<IdentityMetadata> getMetadata(const std::string &identityId) const;

    /// Update metadata
    bool updateMetadata(const std::string &identityId, const std::unordered_map<std::string, std::string> &fields);

    // Access Control

    /// Grant permissions
    bool grantPermissions(const std::string &identityId, const std::vector<IdentityPermission> &permissions,
                          const std::optional<std::chrono::system_clock::time_point> &expiresAt = std::nullopt);

    /// Revoke permissions
    bool revokePermissions(const std::string &identityId);

    /// Check permissions
    bool hasPermission(const std::string &identityId, IdentityPermission permission) const;

    /// Get access control
    std::optional<IdentityAccessControl> getAccessControl(const std::string &identityId) const;

    // Event Management

    /// Add event
    void addEvent(IdentityEventType type, const std::string &identityId,
                  const std::string &description = "",
                  const std::unordered_map<std::string, std::string> &metadata = {});

    /// Get events
    std::vector<IdentityEvent> getEvents(const std::string &identityId = "") const;

    /// Clear old events
    void clearOldEvents(const std::chrono::system_clock::time_point &before);

    // Backup and Restore

    /// Create backup
    std::optional<IdentityBackup> createBackup() const;

    /// Restore from backup
    bool restoreFromBackup(const IdentityBackup &backup);

    /// Export backup to file
    bool exportBackup(const std::string &filePath) const;

    /// Import backup from file
    bool importBackup(const std::string &filePath);

    // Callbacks

    void setOnIdentityCreated(std::function<void(const Identity &)> callback);
    void setOnIdentityUpdated(std::function<void(const Identity &)> callback);
    void setOnIdentityDeleted(std::function<void(const std::string &)> callback);
    void setOnStateChanged(std::function<void(IdentityState)> callback);
    void setOnEventOccurred(std::function<void(const IdentityEvent &)> callback);

private:
    // File operations
    bool ensureDataDirectory();
    bool saveIdentities();
    bool loadIdentities();
    bool saveState();
    bool loadState();
    bool saveRecoveryData();
    bool loadRecoveryData();
    bool saveVerifications();
    bool loadVerifications();
    bool saveMetadata();
    bool loadMetadata();
    bool saveAccessControls();
    bool loadAccessControls();
    bool saveEvents();
    bool loadEvents();

    // Utility
    void logEvent(IdentityEventType type, const std::string &identityId,
                  const std::string &description = "",
                  const std::unordered_map<std::string, std::string> &metadata = {});
    std::string generateIdentityId() const;
    IdentityFingerprint generateFingerprint(const IdentityPublicKey &publicKey) const;
};

} // namespace identity
} // namespace bitchat
