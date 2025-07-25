#pragma once

#include "bitchat/noise/noise_protocol.h"
#include <string>

namespace bitchat
{

enum class NoisePQHandshakePatternType
{
    XX,
    XX_PQ,
    IK,
    IK_PQ,
    XXfallback,
    XXfallback_PQ
};

class NoisePQHandshakePattern
{
public:
    explicit NoisePQHandshakePattern(NoisePQHandshakePatternType type);

    // Pattern information
    NoisePQHandshakePatternType getType() const;
    std::string getTypeString() const;
    bool isPostQuantum() const;
    size_t getMessageCount() const;

    // Pattern strings
    // Get pattern string (e.g., "Noise_XX_25519_ChaChaPoly_SHA256")
    std::string getPatternString() const;
    // Get post-quantum pattern string (e.g., "Noise_XX_PQ_25519_ChaChaPoly_SHA256")
    std::string getPostQuantumPatternString() const;

private:
    NoisePQHandshakePatternType type;
};

} // namespace bitchat
