#pragma once

#include <array>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace bitchat
{

using NoiseSymmetricKey = std::array<uint8_t, 32>;
using NoisePublicKey = std::array<uint8_t, 32>;
using NoisePrivateKey = std::array<uint8_t, 32>;
using NoiseSharedSecret = std::array<uint8_t, 32>;

} // namespace bitchat
