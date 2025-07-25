#pragma once

#include "bitchat/noise/noise_pq_handshake_pattern.h"
#include "bitchat/noise/noise_protocol.h"
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace bitchat
{

enum class NoiseMigrationStrategy
{
    None,
    Gradual,
    Immediate,
    Fallback
};

class NoiseProtocolMigration
{
public:
    explicit NoiseProtocolMigration(NoiseMigrationStrategy strategy = NoiseMigrationStrategy::None);

    // Migration strategy
    NoiseMigrationStrategy getStrategy() const;
    void setStrategy(NoiseMigrationStrategy strategy);

    // Post-quantum support
    bool isPostQuantumSupported() const;
    void setPostQuantumSupported(bool supported);

    // Migration operations
    bool shouldMigrate(const std::string &peerID) const;
    std::string getMigrationPattern(const std::string &peerID) const;
    bool canMigrate(const std::string &peerID) const;

    // Migration state
    bool isMigrationInProgress(const std::string &peerID) const;
    void startMigration(const std::string &peerID);
    void completeMigration(const std::string &peerID);
    void abortMigration(const std::string &peerID);

    // Migration statistics
    size_t getMigrationCount() const;
    size_t getSuccessfulMigrations() const;
    size_t getFailedMigrations() const;

    // Additional methods that are implemented
    bool isMigrationNeeded(const std::string &currentPattern, const std::string &targetPattern) const;
    std::string getRecommendedPattern(const std::string &currentPattern, bool pqSupported) const;
    bool isFallbackNeeded(const std::string &pattern) const;
    std::string getFallbackPattern(const std::string &pattern) const;
    bool isValidMigrationPath(const std::string &fromPattern, const std::string &toPattern) const;

private:
    NoiseMigrationStrategy strategy;
    bool pqSupported;

    // Static member for valid migration paths
    static const std::vector<std::pair<std::string, std::string>> validMigrationPaths;
};

} // namespace bitchat
