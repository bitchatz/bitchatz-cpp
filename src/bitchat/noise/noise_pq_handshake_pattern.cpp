#include "bitchat/noise/noise_pq_handshake_pattern.h"

namespace bitchat
{

NoisePQHandshakePattern::NoisePQHandshakePattern(NoisePQHandshakePatternType type)
    : type(type)
{
}

NoisePQHandshakePatternType NoisePQHandshakePattern::getType() const
{
    return type;
}

std::string NoisePQHandshakePattern::getTypeString() const
{
    switch (type)
    {
    case NoisePQHandshakePatternType::XX:
        return "XX";
    case NoisePQHandshakePatternType::XX_PQ:
        return "XX_PQ";
    case NoisePQHandshakePatternType::IK:
        return "IK";
    case NoisePQHandshakePatternType::IK_PQ:
        return "IK_PQ";
    case NoisePQHandshakePatternType::XXfallback:
        return "XXfallback";
    case NoisePQHandshakePatternType::XXfallback_PQ:
        return "XXfallback_PQ";
    default:
        return "Unknown";
    }
}

bool NoisePQHandshakePattern::isPostQuantum() const
{
    switch (type)
    {
    case NoisePQHandshakePatternType::XX_PQ:
    case NoisePQHandshakePatternType::IK_PQ:
    case NoisePQHandshakePatternType::XXfallback_PQ:
        return true;
    default:
        return false;
    }
}

size_t NoisePQHandshakePattern::getMessageCount() const
{
    switch (type)
    {
    case NoisePQHandshakePatternType::XX:
    case NoisePQHandshakePatternType::XX_PQ:
        return 3;
    case NoisePQHandshakePatternType::IK:
    case NoisePQHandshakePatternType::IK_PQ:
        return 2;
    case NoisePQHandshakePatternType::XXfallback:
    case NoisePQHandshakePatternType::XXfallback_PQ:
        return 1;
    default:
        return 0;
    }
}

std::string NoisePQHandshakePattern::getPatternString() const
{
    switch (type)
    {
    case NoisePQHandshakePatternType::XX:
        return "Noise_XX_25519_ChaChaPoly_SHA256";
    case NoisePQHandshakePatternType::XX_PQ:
        return "Noise_XX_PQ_25519_ChaChaPoly_SHA256";
    case NoisePQHandshakePatternType::IK:
        return "Noise_IK_25519_ChaChaPoly_SHA256";
    case NoisePQHandshakePatternType::IK_PQ:
        return "Noise_IK_PQ_25519_ChaChaPoly_SHA256";
    case NoisePQHandshakePatternType::XXfallback:
        return "Noise_XXfallback_25519_ChaChaPoly_SHA256";
    case NoisePQHandshakePatternType::XXfallback_PQ:
        return "Noise_XXfallback_PQ_25519_ChaChaPoly_SHA256";
    default:
        return "Unknown";
    }
}

std::string NoisePQHandshakePattern::getPostQuantumPatternString() const
{
    switch (type)
    {
    case NoisePQHandshakePatternType::XX_PQ:
        return "Noise_XX_PQ_25519_ChaChaPoly_SHA256";
    case NoisePQHandshakePatternType::IK_PQ:
        return "Noise_IK_PQ_25519_ChaChaPoly_SHA256";
    case NoisePQHandshakePatternType::XXfallback_PQ:
        return "Noise_XXfallback_PQ_25519_ChaChaPoly_SHA256";
    default:
        return "Noise_XX_25519_ChaChaPoly_SHA256"; // Fallback to classical
    }
}

} // namespace bitchat
