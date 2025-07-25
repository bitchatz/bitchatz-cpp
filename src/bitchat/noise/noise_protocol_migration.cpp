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
    : strategy_(strategy)
    , pqSupported_(true) // Assume PQ is supported by default
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
    return strategy_;
}

void NoiseProtocolMigration::setStrategy(NoiseMigrationStrategy strategy)
{
    strategy_ = strategy;
}

bool NoiseProtocolMigration::isPostQuantumSupported() const
{
    return pqSupported_;
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
    switch (strategy_)
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

    case NoiseMigrationStrategy::Opportunistic:
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

    case NoiseMigrationStrategy::Gradual:
        // Implement gradual migration logic
        break;

    case NoiseMigrationStrategy::Fallback:
        // Always use fallback patterns
        return getFallbackPattern(currentPattern);
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
