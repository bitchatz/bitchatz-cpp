#pragma once

#include "bitchat/noise/noise_protocol.h"
#include <string>
#include <vector>

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

    // Get pattern name
    std::string getName() const;

    // Get pattern type
    NoisePQHandshakePatternType getType() const;

    // Check if pattern supports post-quantum
    bool isPostQuantum() const;

    // Get number of handshake messages
    size_t getMessageCount() const;

    // Get pattern description
    std::string getDescription() const;

    // Get pattern string (e.g., "Noise_XX_25519_ChaChaPoly_SHA256")
    std::string getPatternString() const;

    // Get post-quantum pattern string (e.g., "Noise_XX_PQ_25519_ChaChaPoly_SHA256")
    std::string getPQPatternString() const;

private:
    NoisePQHandshakePatternType type_;
};

} // namespace bitchat
