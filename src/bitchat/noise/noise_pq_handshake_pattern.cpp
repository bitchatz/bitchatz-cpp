#include "bitchat/noise/noise_pq_handshake_pattern.h"

namespace bitchat
{

NoisePQHandshakePattern::NoisePQHandshakePattern(NoisePQHandshakePatternType type)
    : type_(type)
{
}

std::string NoisePQHandshakePattern::getName() const
{
    switch (type_)
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

NoisePQHandshakePatternType NoisePQHandshakePattern::getType() const
{
    return type_;
}

bool NoisePQHandshakePattern::isPostQuantum() const
{
    switch (type_)
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
    switch (type_)
    {
    case NoisePQHandshakePatternType::XX:
    case NoisePQHandshakePatternType::XX_PQ:
        return 3;
    case NoisePQHandshakePatternType::IK:
    case NoisePQHandshakePatternType::IK_PQ:
        return 2;
    case NoisePQHandshakePatternType::XXfallback:
    case NoisePQHandshakePatternType::XXfallback_PQ:
        return 2;
    default:
        return 0;
    }
}

std::string NoisePQHandshakePattern::getDescription() const
{
    switch (type_)
    {
    case NoisePQHandshakePatternType::XX:
        return "Three-message handshake with mutual authentication";
    case NoisePQHandshakePatternType::XX_PQ:
        return "Three-message handshake with mutual authentication and post-quantum security";
    case NoisePQHandshakePatternType::IK:
        return "Two-message handshake with pre-shared static keys";
    case NoisePQHandshakePatternType::IK_PQ:
        return "Two-message handshake with pre-shared static keys and post-quantum security";
    case NoisePQHandshakePatternType::XXfallback:
        return "Two-message fallback handshake";
    case NoisePQHandshakePatternType::XXfallback_PQ:
        return "Two-message fallback handshake with post-quantum security";
    default:
        return "Unknown pattern";
    }
}

std::string NoisePQHandshakePattern::getPatternString() const
{
    switch (type_)
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

std::string NoisePQHandshakePattern::getPQPatternString() const
{
    if (isPostQuantum())
    {
        return getPatternString();
    }
    else
    {
        // Convert to PQ pattern
        switch (type_)
        {
        case NoisePQHandshakePatternType::XX:
            return "Noise_XX_PQ_25519_ChaChaPoly_SHA256";
        case NoisePQHandshakePatternType::IK:
            return "Noise_IK_PQ_25519_ChaChaPoly_SHA256";
        case NoisePQHandshakePatternType::XXfallback:
            return "Noise_XXfallback_PQ_25519_ChaChaPoly_SHA256";
        default:
            return getPatternString();
        }
    }
}

} // namespace bitchat
