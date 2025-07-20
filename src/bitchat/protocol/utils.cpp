#include "bitchat/protocol/utils.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

#ifdef __APPLE__
#include <uuid/uuid.h>
#endif

namespace bitchat
{

std::string ProtocolUtils::toHex(const std::vector<uint8_t> &data)
{
    std::stringstream ss;
    for (size_t i = 0; i < data.size(); ++i)
    {
        if (i > 0)
            ss << " ";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string ProtocolUtils::toHexCompact(const std::vector<uint8_t> &data)
{
    std::stringstream ss;
    for (uint8_t byte : data)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> ProtocolUtils::stringToVector(const std::string &str)
{
    // Convert hex string to bytes
    if (str.length() % 2 != 0)
    {
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> result;
    for (size_t i = 0; i < str.length(); i += 2)
    {
        std::string byteString = str.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

std::string ProtocolUtils::vectorToString(const std::vector<uint8_t> &vec)
{
    return std::string(vec.begin(), vec.end());
}

std::string ProtocolUtils::normalizePeerId(const std::string &peerId)
{
    std::string normalized = peerId;
    normalized.erase(std::remove(normalized.begin(), normalized.end(), '\0'), normalized.end());
    return normalized;
}

std::string ProtocolUtils::randomPeerId()
{
    std::vector<uint8_t> peerId(8); // 8 bytes like Swift
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (auto &byte : peerId)
    {
        byte = static_cast<uint8_t>(dis(gen));
    }

    std::stringstream ss;
    for (uint8_t byte : peerId)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::string ProtocolUtils::uuidv4()
{
#ifdef __APPLE__
    uuid_t uuid;
    char uuidStr[37];
    uuid_generate(uuid);
    uuid_unparse_lower(uuid, uuidStr);
    return std::string(uuidStr);
#else
    // Fallback implementation for other platforms
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < 32; ++i)
    {
        if (i == 8 || i == 12 || i == 16 || i == 20)
        {
            ss << "-";
        }
        ss << dis(gen);
    }

    return ss.str();
#endif
}

std::string ProtocolUtils::randomNickname()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);

    return "anon" + std::to_string(dis(gen));
}

bool ProtocolUtils::isValidPeerId(const std::string &peerId)
{
    if (peerId.empty())
        return false;
    if (peerId.length() != 16) // Must be exactly 16 hex characters (8 bytes)
        return false;

    // Check if it contains only hex characters
    return std::all_of(peerId.begin(), peerId.end(), [](char c)
                       { return std::isxdigit(c); });
}

bool ProtocolUtils::isValidChannelName(const std::string &channel)
{
    if (channel.empty())
        return false;
    if (channel.length() > 50)
        return false;
    if (channel[0] != '#')
        return false;

    // Check if it contains only alphanumeric characters and underscores
    return std::all_of(channel.begin() + 1, channel.end(), [](char c)
                       { return std::isalnum(c) || c == '_' || c == '-'; });
}

bool ProtocolUtils::isValidNickname(const std::string &nickname)
{
    if (nickname.empty())
        return false;
    if (nickname.length() > 32)
        return false;

    // Check if it contains only alphanumeric characters, underscores, and hyphens
    return std::all_of(nickname.begin(), nickname.end(), [](char c)
                       { return std::isalnum(c) || c == '_' || c == '-'; });
}

uint64_t ProtocolUtils::getCurrentTimestamp()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string ProtocolUtils::formatTimestamp(uint64_t timestamp)
{
    time_t time = timestamp / 1000;
    char timebuf[20];
    std::tm *tinfo = std::localtime(&time);
    std::strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tinfo);
    return std::string(timebuf);
}

} // namespace bitchat
