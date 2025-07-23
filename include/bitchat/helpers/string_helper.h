#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bitchat
{

// Helper class for string-related helper functions
class StringHelper
{
public:
    // Hex conversion utilities
    static std::string toHex(const std::vector<uint8_t> &data);

    // String/vector conversion utilities
    static std::vector<uint8_t> stringToVector(const std::string &str);
    static std::string vectorToString(const std::vector<uint8_t> &vec);

    // Peer ID utilities
    static std::string normalizePeerID(const std::string &peerID);
    static std::string randomPeerID();

    // UUID utilities
    static std::string uuidv4();

    // Nickname utilities
    static std::string randomNickname();

private:
    StringHelper() = delete;
};

} // namespace bitchat
