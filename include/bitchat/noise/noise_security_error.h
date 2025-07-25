#pragma once

#include <stdexcept>
#include <string>

namespace bitchat
{

enum class NoiseSecurityErrorType
{
    SessionExpired,
    SessionExhausted,
    MessageTooLarge,
    InvalidPeerID,
    InvalidChannelName,
    RateLimitExceeded,
    HandshakeTimeout,
    EncryptionFailed,
    DecryptionFailed,
    InvalidHandshakeMessage,
    KeyGenerationFailed
};

class NoiseSecurityError : public std::runtime_error
{
public:
    explicit NoiseSecurityError(NoiseSecurityErrorType type, const std::string &message = "")
        : std::runtime_error(message.empty() ? getDefaultMessage(type) : message)
        , type_(type)
    {
    }

    NoiseSecurityErrorType getType() const
    {
        return type_;
    }

private:
    static std::string getDefaultMessage(NoiseSecurityErrorType type);

    NoiseSecurityErrorType type_;
};

} // namespace bitchat
