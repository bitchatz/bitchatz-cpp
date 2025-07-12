#include "bitchat/protocol/packet.h"
#include <random>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef __APPLE__
#include <uuid/uuid.h>
#endif

namespace bitchat {

std::string packetTypeToString(uint8_t type) {
    switch (type) {
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

std::string toHex(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) ss << " ";
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}

std::string toHexCompact(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (uint8_t byte : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<uint8_t> stringToVector(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

std::string vectorToString(const std::vector<uint8_t>& vec) {
    return std::string(vec.begin(), vec.end());
}

std::string normalizePeerId(const std::string& peerId) {
    std::string normalized = peerId;
    normalized.erase(std::remove(normalized.begin(), normalized.end(), '\0'), normalized.end());
    return normalized;
}

std::string randomPeerId() {
    std::vector<uint8_t> peerid(4);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (auto& byte : peerid) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    std::stringstream ss;
    for (uint8_t byte : peerid) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

std::string uuidv4() {
#ifdef __APPLE__
    uuid_t uuid;
    char uuid_str[37];
    uuid_generate(uuid);
    uuid_unparse_lower(uuid, uuid_str);
    return std::string(uuid_str);
#else
    // Fallback implementation for other platforms
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    ss << std::hex;
    
    for (int i = 0; i < 32; ++i) {
        if (i == 8 || i == 12 || i == 16 || i == 20) {
            ss << "-";
        }
        ss << dis(gen);
    }
    
    return ss.str();
#endif
}

std::string randomNickname() {
    std::vector<std::string> adjectives = {
        "Swift", "Fast", "Quick", "Bright", "Smart", "Clever", "Wise", "Sharp",
        "Bold", "Brave", "Calm", "Cool", "Dark", "Deep", "Fair", "Fine",
        "Free", "Good", "Great", "High", "Kind", "Light", "Long", "Loud",
        "New", "Nice", "Old", "Open", "Pure", "Rich", "Safe", "Soft",
        "Sweet", "Tall", "True", "Warm", "Wild", "Young", "Zesty", "Vivid"
    };
    
    std::vector<std::string> nouns = {
        "Fox", "Wolf", "Bear", "Eagle", "Hawk", "Lion", "Tiger", "Dragon",
        "Phoenix", "Raven", "Swan", "Falcon", "Owl", "Shark", "Whale", "Dolphin",
        "Panda", "Koala", "Kangaroo", "Elephant", "Giraffe", "Zebra", "Cheetah",
        "Leopard", "Jaguar", "Panther", "Lynx", "Bobcat", "Coyote", "Jackal",
        "Viper", "Cobra", "Python", "Anaconda", "Rattlesnake", "Mamba", "Asp",
        "Shark", "Orca", "Narwhal", "Seahorse", "Starfish", "Jellyfish"
    };
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> adjDis(0, adjectives.size() - 1);
    std::uniform_int_distribution<> nounDis(0, nouns.size() - 1);
    
    return adjectives[adjDis(gen)] + nouns[nounDis(gen)];
}

} // namespace bitchat 