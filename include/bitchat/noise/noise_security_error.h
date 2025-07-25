#pragma once

#include <stdexcept>
#include <string>

namespace bitchat
{

enum class NoiseSecurityErrorType
{
    None,
    InvalidHandshakeMessage,
    InvalidPeerID,
    KeyGenerationFailed,
    SessionExpired,
    MessageLimitExceeded,
    InvalidCiphertext,
    HandshakeTimeout,
    InvalidState,
    UnsupportedAlgorithm
};

class NoiseSecurityError : public std::runtime_error
{
public:
    explicit NoiseSecurityError(NoiseSecurityErrorType type, const std::string &message = "")
        : std::runtime_error(message.empty() ? getDefaultMessage(type) : message)
        , type(type)
    {
    }

    NoiseSecurityErrorType getType() const
    {
        return type;
    }

private:
    static std::string getDefaultMessage(NoiseSecurityErrorType type);
    NoiseSecurityErrorType type;
};

} // namespace bitchat
