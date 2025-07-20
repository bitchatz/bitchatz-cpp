#include "bitchat/protocol/message_padding.h"
#include <algorithm>
#include <random>
#include <spdlog/spdlog.h>

namespace bitchat
{

std::vector<uint8_t> MessagePadding::pad(const std::vector<uint8_t> &data, size_t targetSize)
{
    if (data.size() >= targetSize)
    {
        return data;
    }

    size_t paddingNeeded = targetSize - data.size();

    // PKCS#7 only supports padding up to 255 bytes
    // If we need more padding than that, don't pad - return original data
    if (paddingNeeded > 255)
    {
        return data;
    }

    std::vector<uint8_t> padded = data;

    // Standard PKCS#7 padding
    std::vector<uint8_t> randomBytes(paddingNeeded - 1);

    // Generate random bytes
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (auto &byte : randomBytes)
    {
        byte = static_cast<uint8_t>(dis(gen));
    }

    padded.insert(padded.end(), randomBytes.begin(), randomBytes.end());
    padded.push_back(static_cast<uint8_t>(paddingNeeded));

    return padded;
}

std::vector<uint8_t> MessagePadding::unpad(const std::vector<uint8_t> &data)
{
    if (data.empty())
    {
        return data;
    }

    // Last byte tells us how much padding to remove
    uint8_t paddingLength = data.back();

    if (paddingLength == 0 || paddingLength > data.size())
    {
        // Debug logging for 243-byte packets
        if (data.size() == 243)
        {
            spdlog::debug("Invalid padding length {} for 243-byte packet", paddingLength);
        }
        return data;
    }

    std::vector<uint8_t> result(data.begin(), data.begin() + data.size() - paddingLength);

    // Debug logging for 243-byte packets
    if (data.size() == 243)
    {
        spdlog::debug("Unpadded 243-byte packet to {} bytes", result.size());
    }

    return result;
}

size_t MessagePadding::optimalBlockSize(size_t dataSize)
{
    // Account for encryption overhead (~16 bytes for AES-GCM tag)
    size_t totalSize = dataSize + 16;

    // Find smallest block that fits
    for (size_t blockSize : blockSizes)
    {
        if (totalSize <= blockSize)
        {
            return blockSize;
        }
    }

    // For very large messages, just use the original size
    // (will be fragmented anyway)
    return dataSize;
}

} // namespace bitchat
