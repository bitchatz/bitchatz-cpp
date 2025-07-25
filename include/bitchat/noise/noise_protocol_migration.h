#pragma once

#include "bitchat/noise/noise_pq_handshake_pattern.h"
#include "bitchat/noise/noise_protocol.h"
#include <memory>
#include <string>

namespace bitchat
{

enum class NoiseMigrationStrategy
{
    Immediate,     // Migrate immediately when PQ is available
    Opportunistic, // Migrate when both parties support PQ
    Gradual,       // Migrate gradually over time
    Fallback       // Use fallback pattern if PQ fails
};

class NoiseProtocolMigration
{
public:
    explicit NoiseProtocolMigration(NoiseMigrationStrategy strategy = NoiseMigrationStrategy::Opportunistic);

    // Check if migration is needed
    bool isMigrationNeeded(const std::string &currentPattern, const std::string &targetPattern) const;

    // Get migration strategy
    NoiseMigrationStrategy getStrategy() const;

    // Set migration strategy
    void setStrategy(NoiseMigrationStrategy strategy);

    // Check if post-quantum migration is supported
    bool isPostQuantumSupported() const;

    // Get recommended pattern for migration
    std::string getRecommendedPattern(const std::string &currentPattern, bool pqSupported) const;

    // Check if fallback is needed
    bool isFallbackNeeded(const std::string &pattern) const;

    // Get fallback pattern
    std::string getFallbackPattern(const std::string &pattern) const;

    // Validate migration path
    bool isValidMigrationPath(const std::string &fromPattern, const std::string &toPattern) const;

private:
    NoiseMigrationStrategy strategy_;
    bool pqSupported_;

    // Migration paths
    static const std::vector<std::pair<std::string, std::string>> validMigrationPaths;
};

} // namespace bitchat
