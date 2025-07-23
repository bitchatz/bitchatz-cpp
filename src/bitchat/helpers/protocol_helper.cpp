#include "bitchat/helpers/protocol_helper.h"
#include <algorithm>

namespace bitchat
{

bool ProtocolHelper::isValidPeerID(const std::string &peerID)
{
    // Check if the peerID is empty
    if (peerID.empty())
    {
        return false;
    }

    // Must be exactly 16 hex characters (8 bytes)
    if (peerID.length() != 16)
    {
        return false;
    }

    // Check if it contains only hex characters
    // clang-format off
    return std::all_of(peerID.begin(), peerID.end(), [](char c) {
        return std::isxdigit(c);
    });
    // clang-format on
}

bool ProtocolHelper::isValidChannelName(const std::string &channel)
{
    // Check if the channel is empty
    if (channel.empty())
    {
        return false;
    }

    // Check if the channel is too long
    if (channel.length() > 50)
    {
        return false;
    }

    // Check if the channel starts with a #
    if (channel[0] != '#')
    {
        return false;
    }

    // Check if it contains only alphanumeric characters and underscores
    // clang-format off
    return std::all_of(channel.begin() + 1, channel.end(), [](char c) {
        return std::isalnum(c) || c == '_' || c == '-';
    });
    // clang-format on
}

bool ProtocolHelper::isValidNickname(const std::string &nickname)
{
    // Check if the nickname is empty
    if (nickname.empty())
    {
        return false;
    }

    // Check if the nickname is too long
    if (nickname.length() > 32)
    {
        return false;
    }

    // Check if it contains only alphanumeric characters, underscores, and hyphens
    // clang-format off
    return std::all_of(nickname.begin(), nickname.end(), [](char c) {
        return std::isalnum(c) || c == '_' || c == '-';
    });
    // clang-format on
}

} // namespace bitchat
