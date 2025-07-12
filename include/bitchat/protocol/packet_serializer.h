#pragma once

#include "packet.h"
#include <vector>

namespace bitchat {

// PacketSerializer: handles serialization and deserialization of packets
class PacketSerializer {
public:
    PacketSerializer();
    ~PacketSerializer() = default;

    // Serialize packet to binary data
    std::vector<uint8_t> serializePacket(const BitchatPacket& packet);
    
    // Deserialize binary data to packet
    BitchatPacket deserializePacket(const std::vector<uint8_t>& data);
    
    // Create message payload
    std::vector<uint8_t> makeMessagePayload(const BitchatMessage& message);
    
    // Parse message payload
    BitchatMessage parseMessagePayload(const std::vector<uint8_t>& payload);
    
    // Create announce payload
    std::vector<uint8_t> makeAnnouncePayload(const std::string& nickname);
    
    // Parse announce payload
    void parseAnnouncePayload(const std::vector<uint8_t>& payload, std::string& nickname);
    
    // Create packet with proper fields
    BitchatPacket makePacket(uint8_t type, const std::vector<uint8_t>& payload,
                            bool hasRecipient = false, bool hasSignature = false,
                            const std::string& senderId = "");

private:
    // Helper functions for serialization
    void writeUint64(std::vector<uint8_t>& data, uint64_t value);
    void writeUint16(std::vector<uint8_t>& data, uint16_t value);
    void writeUint8(std::vector<uint8_t>& data, uint8_t value);
    
    // Helper functions for deserialization
    uint64_t readUint64(const std::vector<uint8_t>& data, size_t& offset);
    uint16_t readUint16(const std::vector<uint8_t>& data, size_t& offset);
    uint8_t readUint8(const std::vector<uint8_t>& data, size_t& offset);
    
    // Validate packet size
    bool validatePacketSize(const std::vector<uint8_t>& data, size_t expectedSize);
};

} // namespace bitchat 