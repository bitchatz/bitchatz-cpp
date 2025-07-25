#include "bitchat/noise/noise_protocol_migration.h"
#include <algorithm>

namespace bitchat
{

// Define valid migration paths
const std::vector<std::pair<std::string, std::string>> NoiseProtocolMigration::validMigrationPaths = {
    {"Noise_XX_25519_ChaChaPoly_SHA256", "Noise_XX_PQ_25519_ChaChaPoly_SHA256"},
    {"Noise_IK_25519_ChaChaPoly_SHA256", "Noise_IK_PQ_25519_ChaChaPoly_SHA256"},
    {"Noise_XX_25519_ChaChaPoly_SHA256", "Noise_XXfallback_25519_ChaChaPoly_SHA256"},
    {"Noise_XX_PQ_25519_ChaChaPoly_SHA256", "Noise_XXfallback_PQ_25519_ChaChaPoly_SHA256"},
    {"Noise_XXfallback_25519_ChaChaPoly_SHA256", "Noise_XXfallback_PQ_25519_ChaChaPoly_SHA256"}};

NoiseProtocolMigration::NoiseProtocolMigration(NoiseMigrationStrategy strategy)
    : strategy(strategy)
    , pqSupported(false)
{
}

bool NoiseProtocolMigration::isMigrationNeeded(const std::string &currentPattern, const std::string &targetPattern) const
{
    if (currentPattern == targetPattern)
    {
        return false;
    }

    // Check if this is a valid migration path
    return isValidMigrationPath(currentPattern, targetPattern);
}

NoiseMigrationStrategy NoiseProtocolMigration::getStrategy() const
{
    return strategy;
}

void NoiseProtocolMigration::setStrategy(NoiseMigrationStrategy strategy)
{
    this->strategy = strategy;
}

bool NoiseProtocolMigration::isPostQuantumSupported() const
{
    return pqSupported;
}

void NoiseProtocolMigration::setPostQuantumSupported(bool supported)
{
    pqSupported = supported;
}

bool NoiseProtocolMigration::shouldMigrate([[maybe_unused]] const std::string &peerID) const
{
    // Implementation would check if migration is needed for this peer
    return false;
}

std::string NoiseProtocolMigration::getMigrationPattern([[maybe_unused]] const std::string &peerID) const
{
    // Implementation would return the appropriate migration pattern
    return "Noise_XX_25519_ChaChaPoly_SHA256";
}

bool NoiseProtocolMigration::canMigrate([[maybe_unused]] const std::string &peerID) const
{
    // Implementation would check if migration is possible
    return false;
}

bool NoiseProtocolMigration::isMigrationInProgress([[maybe_unused]] const std::string &peerID) const
{
    // Implementation would check migration state
    return false;
}

void NoiseProtocolMigration::startMigration([[maybe_unused]] const std::string &peerID)
{
    // Implementation would start migration process
}

void NoiseProtocolMigration::completeMigration([[maybe_unused]] const std::string &peerID)
{
    // Implementation would complete migration process
}

void NoiseProtocolMigration::abortMigration([[maybe_unused]] const std::string &peerID)
{
    // Implementation would abort migration process
}

size_t NoiseProtocolMigration::getMigrationCount() const
{
    // Implementation would return total migration count
    return 0;
}

size_t NoiseProtocolMigration::getSuccessfulMigrations() const
{
    // Implementation would return successful migration count
    return 0;
}

size_t NoiseProtocolMigration::getFailedMigrations() const
{
    // Implementation would return failed migration count
    return 0;
}

std::string NoiseProtocolMigration::getRecommendedPattern(const std::string &currentPattern, bool pqSupported) const
{
    if (!pqSupported)
    {
        // If PQ is not supported, recommend fallback patterns
        if (currentPattern.find("_PQ_") != std::string::npos)
        {
            return getFallbackPattern(currentPattern);
        }
        return currentPattern;
    }

    // If PQ is supported, recommend PQ patterns based on strategy
    switch (strategy)
    {
    case NoiseMigrationStrategy::Immediate:
        if (currentPattern.find("_PQ_") == std::string::npos)
        {
            // Convert to PQ pattern
            if (currentPattern.find("Noise_XX_") != std::string::npos)
            {
                return "Noise_XX_PQ_25519_ChaChaPoly_SHA256";
            }
            else if (currentPattern.find("Noise_IK_") != std::string::npos)
            {
                return "Noise_IK_PQ_25519_ChaChaPoly_SHA256";
            }
        }
        break;

    case NoiseMigrationStrategy::Gradual:
        // Only migrate if both parties support PQ
        if (currentPattern.find("_PQ_") == std::string::npos)
        {
            if (currentPattern.find("Noise_XX_") != std::string::npos)
            {
                return "Noise_XX_PQ_25519_ChaChaPoly_SHA256";
            }
            else if (currentPattern.find("Noise_IK_") != std::string::npos)
            {
                return "Noise_IK_PQ_25519_ChaChaPoly_SHA256";
            }
        }
        break;

    case NoiseMigrationStrategy::Fallback:
        // Always use fallback patterns
        return getFallbackPattern(currentPattern);

    case NoiseMigrationStrategy::None:
        // No migration
        break;
    }

    return currentPattern;
}

bool NoiseProtocolMigration::isFallbackNeeded(const std::string &pattern) const
{
    // Check if pattern contains fallback indicators
    return pattern.find("fallback") != std::string::npos;
}

std::string NoiseProtocolMigration::getFallbackPattern(const std::string &pattern) const
{
    if (pattern.find("Noise_XX_") != std::string::npos)
    {
        if (pattern.find("_PQ_") != std::string::npos)
        {
            return "Noise_XXfallback_PQ_25519_ChaChaPoly_SHA256";
        }
        else
        {
            return "Noise_XXfallback_25519_ChaChaPoly_SHA256";
        }
    }
    else if (pattern.find("Noise_IK_") != std::string::npos)
    {
        if (pattern.find("_PQ_") != std::string::npos)
        {
            return "Noise_XXfallback_PQ_25519_ChaChaPoly_SHA256";
        }
        else
        {
            return "Noise_XXfallback_25519_ChaChaPoly_SHA256";
        }
    }

    return pattern;
}

bool NoiseProtocolMigration::isValidMigrationPath(const std::string &fromPattern, const std::string &toPattern) const
{
    auto it = std::find_if(validMigrationPaths.begin(), validMigrationPaths.end(),
                           [&](const std::pair<std::string, std::string> &path)
                           {
                               return path.first == fromPattern && path.second == toPattern;
                           });

    return it != validMigrationPaths.end();
}

} // namespace bitchat
