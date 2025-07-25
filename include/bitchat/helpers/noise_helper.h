#pragma once

#include "bitchat/noise/noise_role.h"
#include <string>

namespace bitchat
{

class NoiseHelper
{
public:
    static std::string noiseRoleToString(NoiseRole role);
    static NoiseRole noiseRoleFromString(const std::string &roleStr);
};

} // namespace bitchat
