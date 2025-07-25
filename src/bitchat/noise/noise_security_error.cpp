#include "bitchat/noise/noise_security_error.h"

namespace bitchat
{

std::string NoiseSecurityError::getDefaultMessage(NoiseSecurityErrorType type)
{
    switch (type)
    {
    case NoiseSecurityErrorType::None:
        return "No error";
    case NoiseSecurityErrorType::InvalidHandshakeMessage:
        return "Invalid handshake message";
    case NoiseSecurityErrorType::InvalidPeerID:
        return "Invalid peer ID";
    case NoiseSecurityErrorType::KeyGenerationFailed:
        return "Key generation failed";
    case NoiseSecurityErrorType::SessionExpired:
        return "Session expired";
    case NoiseSecurityErrorType::MessageLimitExceeded:
        return "Message limit exceeded";
    case NoiseSecurityErrorType::InvalidCiphertext:
        return "Invalid ciphertext";
    case NoiseSecurityErrorType::HandshakeTimeout:
        return "Handshake timeout";
    case NoiseSecurityErrorType::InvalidState:
        return "Invalid state";
    case NoiseSecurityErrorType::UnsupportedAlgorithm:
        return "Unsupported algorithm";
    default:
        return "Unknown error";
    }
}

} // namespace bitchat
