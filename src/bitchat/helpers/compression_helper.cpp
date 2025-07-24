#include "bitchat/helpers/compression_helper.h"
#include "lz4.h"
#include <algorithm>
#include <spdlog/spdlog.h>

namespace bitchat
{

std::vector<uint8_t> CompressionHelper::compressData(const std::vector<uint8_t> &data)
{
    // Skip compression for small data
    if (!shouldCompress(data))
    {
        return data;
    }

    // Calculate compression bound
    int compressedBound = calculateCompressionBound(data.size());
    std::vector<uint8_t> compressedData(compressedBound);

    // Compress data
    int compressedSize = LZ4_compress_default(
        reinterpret_cast<const char *>(data.data()),
        reinterpret_cast<char *>(compressedData.data()),
        static_cast<int>(data.size()),
        compressedBound);

    if (compressedSize <= 0)
    {
        spdlog::error("Compression failed");

        // Return original data if compression fails
        return data;
    }

    // Resize to actual compressed size
    compressedData.resize(compressedSize);
    spdlog::debug("Compressed {} bytes to {} bytes (ratio: {:.2f}%)", data.size(), compressedSize, (compressedSize * 100.0) / data.size());

    return compressedData;
}

std::vector<uint8_t> CompressionHelper::decompressData(const std::vector<uint8_t> &compressedData, size_t originalSize)
{
    // Allocate buffer for decompressed data
    std::vector<uint8_t> decompressedData(originalSize);

    // Decompress data
    int decompressedSize = LZ4_decompress_safe(
        reinterpret_cast<const char *>(compressedData.data()),
        reinterpret_cast<char *>(decompressedData.data()),
        static_cast<int>(compressedData.size()),
        static_cast<int>(originalSize));

    if (decompressedSize < 0)
    {
        spdlog::error("Decompression failed");

        // Return empty vector if decompression fails
        return std::vector<uint8_t>();
    }

    // Resize to actual decompressed size
    decompressedData.resize(decompressedSize);
    spdlog::debug("Decompressed {} bytes to {} bytes", compressedData.size(), decompressedSize);

    return decompressedData;
}

bool CompressionHelper::shouldCompress(const std::vector<uint8_t> &data)
{
    // Don't compress if data is too small
    return data.size() > COMPRESSION_THRESHOLD;
}

int CompressionHelper::calculateCompressionBound(size_t dataSize)
{
    return LZ4_compressBound(static_cast<int>(dataSize));
}

} // namespace bitchat
