#include "bitchat/helpers/protocol_helper.h"
#include "uuid-v4/uuid-v4.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

namespace bitchat
{

std::string ProtocolHelper::toHex(const std::vector<uint8_t> &data)
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

std::string ProtocolHelper::toHexCompact(const std::vector<uint8_t> &data)
{
    std::stringstream ss;
    for (uint8_t byte : data)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> ProtocolHelper::stringToVector(const std::string &str)
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

std::string ProtocolHelper::vectorToString(const std::vector<uint8_t> &vec)
{
    return std::string(vec.begin(), vec.end());
}

std::string ProtocolHelper::normalizePeerId(const std::string &peerId)
{
    std::string normalized = peerId;
    normalized.erase(std::remove(normalized.begin(), normalized.end(), '\0'), normalized.end());
    return normalized;
}

std::string ProtocolHelper::randomPeerId()
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

std::string ProtocolHelper::uuidv4()
{
    return uuid::v4::UUID::New().String();
}

std::string ProtocolHelper::randomNickname()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);

    return "anon" + std::to_string(dis(gen));
}

bool ProtocolHelper::isValidPeerId(const std::string &peerId)
{
    // Check if the peerId is empty
    if (peerId.empty())
    {
        return false;
    }

    // Must be exactly 16 hex characters (8 bytes)
    if (peerId.length() != 16)
    {
        return false;
    }

    // Check if it contains only hex characters
    return std::all_of(peerId.begin(), peerId.end(), [](char c)
                       { return std::isxdigit(c); });
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
    return std::all_of(channel.begin() + 1, channel.end(), [](char c)
                       { return std::isalnum(c) || c == '_' || c == '-'; });
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
    return std::all_of(nickname.begin(), nickname.end(), [](char c)
                       { return std::isalnum(c) || c == '_' || c == '-'; });
}

uint64_t ProtocolHelper::getCurrentTimestamp()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string ProtocolHelper::formatTimestamp(uint64_t timestamp)
{
    time_t time = timestamp / 1000;
    char timebuf[20];
    std::tm *tinfo = std::localtime(&time);
    std::strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tinfo);
    return std::string(timebuf);
}

} // namespace bitchat
