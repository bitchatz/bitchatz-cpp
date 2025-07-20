#pragma once

#include <cstdint>
#include <vector>

namespace bitchat
{

// MARK: - Privacy-preserving padding utilities

struct MessagePadding
{
    // Standard block sizes for padding
    static constexpr std::array<size_t, 4> blockSizes = {256, 512, 1024, 2048};

    // Add PKCS#7-style padding to reach target size
    static std::vector<uint8_t> pad(const std::vector<uint8_t> &data, size_t targetSize);

    // Remove padding from data
    static std::vector<uint8_t> unpad(const std::vector<uint8_t> &data);

    // Find optimal block size for data
    static size_t optimalBlockSize(size_t dataSize);
};

} // namespace bitchat
