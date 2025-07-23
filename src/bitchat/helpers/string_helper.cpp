#include "bitchat/helpers/string_helper.h"
#include "uuid-v4/uuid-v4.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

namespace bitchat
{

std::string StringHelper::toHex(const std::vector<uint8_t> &data)
{
    std::stringstream ss;

    for (uint8_t byte : data)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return ss.str();
}

std::vector<uint8_t> StringHelper::stringToVector(const std::string &str)
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

std::string StringHelper::vectorToString(const std::vector<uint8_t> &vec)
{
    return std::string(vec.begin(), vec.end());
}

std::string StringHelper::normalizePeerID(const std::string &peerID)
{
    std::string normalized = peerID;
    normalized.erase(std::remove(normalized.begin(), normalized.end(), '\0'), normalized.end());
    return normalized;
}

std::string StringHelper::randomPeerID()
{
    // 8 bytes peer ID
    std::vector<uint8_t> peerID(8);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (auto &byte : peerID)
    {
        byte = static_cast<uint8_t>(dis(gen));
    }

    std::stringstream ss;
    for (uint8_t byte : peerID)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return ss.str();
}

std::string StringHelper::uuidv4()
{
    return uuid::v4::UUID::New().String();
}

std::string StringHelper::randomNickname()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);

    return "anon" + std::to_string(dis(gen));
}

} // namespace bitchat
