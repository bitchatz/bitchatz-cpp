#include "bitchat/compression/compression_manager.h"
#include "lz4.h"
#include <set>
#include <algorithm>

namespace bitchat {

CompressionManager::CompressionManager() = default;

std::vector<uint8_t> CompressionManager::compressData(const std::vector<uint8_t>& data) {
    // Skip compression for small data
    if (data.size() < COMPRESSION_THRESHOLD) {
        return data;
    }

    // Calculate maximum compressed size
    int maxCompressedSize = calculateCompressionBound(data.size());
    if (maxCompressedSize <= 0) {
        return data; // Return original on error
    }

    // Allocate buffer for compressed data
    std::vector<uint8_t> compressed(maxCompressedSize);

    // Compress using LZ4
    int compressedSize = LZ4_compress_default(
        reinterpret_cast<const char*>(data.data()),
        reinterpret_cast<char*>(compressed.data()),
        static_cast<int>(data.size()),
        maxCompressedSize
    );

    if (compressedSize <= 0) {
        return data; // Return original on error
    }

    // Only return compressed if it's actually smaller
    if (compressedSize < static_cast<int>(data.size())) {
        compressed.resize(compressedSize);
        return compressed;
    }

    return data; // Return original if compression didn't help
}

std::vector<uint8_t> CompressionManager::decompressData(const std::vector<uint8_t>& compressedData, 
                                                       size_t originalSize) {
    // Allocate buffer for decompressed data
    std::vector<uint8_t> decompressed(originalSize);

    // Decompress using LZ4
    int decompressedSize = LZ4_decompress_safe(
        reinterpret_cast<const char*>(compressedData.data()),
        reinterpret_cast<char*>(decompressed.data()),
        static_cast<int>(compressedData.size()),
        static_cast<int>(originalSize)
    );

    if (decompressedSize <= 0) {
        return compressedData; // Return original on error
    }

    if (decompressedSize != static_cast<int>(originalSize)) {
        // Size mismatch, resize to actual size
        decompressed.resize(decompressedSize);
    }

    return decompressed;
}

bool CompressionManager::shouldCompress(const std::vector<uint8_t>& data) const {
    // Don't compress if data is too small
    if (data.size() < COMPRESSION_THRESHOLD) {
        return false;
    }

    // Simple entropy check - count unique bytes
    std::set<uint8_t> uniqueBytes(data.begin(), data.end());

    // If we have very high byte diversity, data is likely already compressed
    double uniqueByteRatio = static_cast<double>(uniqueBytes.size()) / 
                             std::min(data.size(), static_cast<size_t>(256));
    return uniqueByteRatio < 0.9; // Compress if less than 90% unique bytes
}

int CompressionManager::calculateCompressionBound(size_t dataSize) const {
    return LZ4_compressBound(static_cast<int>(dataSize));
}

} // namespace bitchat 