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
    // Hex conversion utilities
    static std::string toHex(const std::vector<uint8_t> &data);
    static std::string toHexCompact(const std::vector<uint8_t> &data);

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

    // Validation utilities
    static bool isValidPeerID(const std::string &peerID);
    static bool isValidChannelName(const std::string &channel);
    static bool isValidNickname(const std::string &nickname);

    // Time utilities
    static uint64_t getCurrentTimestamp();
    static std::string formatTimestamp(uint64_t timestamp);

private:
    ProtocolHelper() = delete; // Static class, no instantiation
};

} // namespace bitchat
