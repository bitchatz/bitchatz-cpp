#include "bitchat/protocol/packet.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

#ifdef __APPLE__
#include <uuid/uuid.h>
#endif

namespace bitchat
{

std::string packetTypeToString(uint8_t type)
{
    switch (type)
    {
    case PKT_TYPE_ANNOUNCE:
        return "ANNOUNCE";
    case PKT_TYPE_KEYEXCHANGE:
        return "KEYEXCHANGE";
    case PKT_TYPE_MESSAGE:
        return "MESSAGE";
    case PKT_TYPE_LEAVE:
        return "LEAVE";
    case PKT_TYPE_FRAGMENT_START:
        return "FRAGMENT_START";
    case PKT_TYPE_FRAGMENT_CONTINUE:
        return "FRAGMENT_CONTINUE";
    case PKT_TYPE_FRAGMENT_END:
        return "FRAGMENT_END";
    case PKT_TYPE_CHANNEL_ANNOUNCE:
        return "CHANNEL_ANNOUNCE";
    case PKT_TYPE_CHANNEL_RETENTION:
        return "CHANNEL_RETENTION";
    case PKT_TYPE_DELIVERY_ACK:
        return "DELIVERY_ACK";
    case PKT_TYPE_DELIVERY_STATUS_REQUEST:
        return "DELIVERY_STATUS_REQUEST";
    case PKT_TYPE_READ_RECEIPT:
        return "READ_RECEIPT";
    default:
        return "UNKNOWN";
    }
}

std::string toHex(const std::vector<uint8_t> &data)
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

std::string toHexCompact(const std::vector<uint8_t> &data)
{
    std::stringstream ss;
    for (uint8_t byte : data)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> stringToVector(const std::string &str)
{
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string vectorToString(const std::vector<uint8_t> &vec)
{
    return std::string(vec.begin(), vec.end());
}

std::string normalizePeerId(const std::string &peerId)
{
    std::string normalized = peerId;
    normalized.erase(std::remove(normalized.begin(), normalized.end(), '\0'), normalized.end());
    return normalized;
}

std::string randomPeerId()
{
    std::vector<uint8_t> peerId(4);
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

std::string uuidv4()
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

std::string randomNickname()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);

    return "anon" + std::to_string(dis(gen));
}

} // namespace bitchat
