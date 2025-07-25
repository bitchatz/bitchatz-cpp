#include "bitchat/noise/noise_security_error.h"

namespace bitchat
{

std::string NoiseSecurityError::getDefaultMessage(NoiseSecurityErrorType type)
{
    switch (type)
    {
    case NoiseSecurityErrorType::SessionExpired:
        return "Noise session has expired";
    case NoiseSecurityErrorType::SessionExhausted:
        return "Noise session message limit exceeded";
    case NoiseSecurityErrorType::MessageTooLarge:
        return "Message size exceeds maximum allowed";
    case NoiseSecurityErrorType::InvalidPeerID:
        return "Invalid peer ID provided";
    case NoiseSecurityErrorType::InvalidChannelName:
        return "Invalid channel name provided";
    case NoiseSecurityErrorType::RateLimitExceeded:
        return "Rate limit exceeded";
    case NoiseSecurityErrorType::HandshakeTimeout:
        return "Handshake timeout";
    case NoiseSecurityErrorType::EncryptionFailed:
        return "Message encryption failed";
    case NoiseSecurityErrorType::DecryptionFailed:
        return "Message decryption failed";
    case NoiseSecurityErrorType::InvalidHandshakeMessage:
        return "Invalid handshake message";
    case NoiseSecurityErrorType::KeyGenerationFailed:
        return "Key generation failed";
    default:
        return "Unknown noise security error";
    }
}

} // namespace bitchat
