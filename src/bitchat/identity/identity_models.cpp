#include "bitchat/identity/identity_models.h"
#include "bitchat/core/bitchat_manager.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <spdlog/spdlog.h>

namespace bitchat
{

IdentityData::IdentityData()
{
    // Pass
}

std::string IdentityData::generatePeerID()
{
    return "";
}

std::vector<uint8_t> IdentityData::generateIdentityHash([[maybe_unused]] const std::string &peerID, [[maybe_unused]] const std::string &channelName)
{
    return {};
}

} // namespace bitchat
