#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bitchat
{

// Helper class for protocol-related helper functions
class ProtocolHelper
{
public:
    static bool isValidPeerID(const std::string &peerID);
    static bool isValidChannelName(const std::string &channel);
    static bool isValidNickname(const std::string &nickname);

private:
    ProtocolHelper() = delete;
};

} // namespace bitchat
