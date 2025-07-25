#include "bitchat/helpers/noise_helper.h"
#include <stdexcept>

namespace bitchat
{

std::string NoiseHelper::noiseRoleToString(NoiseRole role)
{
    switch (role)
    {
    case NoiseRole::Initiator:
        return "Initiator";
    case NoiseRole::Responder:
        return "Responder";
    default:
        throw std::invalid_argument("Unknown NoiseRole");
    }
}

NoiseRole NoiseHelper::noiseRoleFromString(const std::string &roleStr)
{
    if (roleStr == "Initiator")
    {
        return NoiseRole::Initiator;
    }
    else if (roleStr == "Responder")
    {
        return NoiseRole::Responder;
    }
    else
    {
        throw std::invalid_argument("Invalid NoiseRole string: " + roleStr);
    }
}

} // namespace bitchat
