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
    auto cryptoService = BitchatManager::shared()->getCryptoService();

    auto randomBytes = cryptoService->generateRandomBytes(8);
    if (randomBytes.empty())
    {
        throw std::runtime_error("Failed to generate random bytes for peer ID");
    }

    std::string peerID;
    for (uint8_t byte : randomBytes)
    {
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", byte);
        peerID += hex;
    }

    return peerID;
}

std::vector<uint8_t> IdentityData::generateIdentityHash(const std::string &peerID, const std::string &channelName)
{
    auto cryptoService = BitchatManager::shared()->getCryptoService();

    std::string combined = peerID + channelName;
    return cryptoService->sha256(combined);
}

} // namespace bitchat
