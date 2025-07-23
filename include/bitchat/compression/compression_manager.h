#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bitchat
{

// CompressionManager: Handles LZ4 compression and decompression
class CompressionManager
{
public:
    CompressionManager();
    ~CompressionManager() = default;

    // Compress data using LZ4
    std::vector<uint8_t> compressData(const std::vector<uint8_t> &data);

    // Decompress data using LZ4
    std::vector<uint8_t> decompressData(const std::vector<uint8_t> &compressedData, size_t originalSize);

    // Check if data should be compressed
    bool shouldCompress(const std::vector<uint8_t> &data) const;

    // Calculate compression bound for given data size
    int calculateCompressionBound(size_t dataSize) const;

private:
    static constexpr size_t COMPRESSION_THRESHOLD = 100; // bytes
};

} // namespace bitchat
