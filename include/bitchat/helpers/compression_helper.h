#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace bitchat
{

// CompressionHelper: Handles compression and decompression
class CompressionHelper
{
public:
    // Compress data
    static std::vector<uint8_t> compressData(const std::vector<uint8_t> &data);

    // Decompress data
    static std::vector<uint8_t> decompressData(const std::vector<uint8_t> &compressedData, size_t originalSize);

    // Check if data should be compressed
    static bool shouldCompress(const std::vector<uint8_t> &data);

    // Calculate compression bound for given data size
    static int calculateCompressionBound(size_t dataSize);

private:
    static constexpr size_t COMPRESSION_THRESHOLD = 100; // bytes

    CompressionHelper() = delete;
};

} // namespace bitchat
