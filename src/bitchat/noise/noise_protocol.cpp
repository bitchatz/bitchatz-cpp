#include "bitchat/noise/noise_protocol.h"
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace bitchat
{
namespace noise
{

std::vector<uint8_t> sha256(const std::vector<uint8_t> &data)
{
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return {};
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx, hash.data(), &hashLen) != 1)
    {
        EVP_MD_CTX_free(ctx);
        return {};
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

std::vector<uint8_t> sha256(const std::string &data)
{
    std::vector<uint8_t> dataBytes(data.begin(), data.end());
    return sha256(dataBytes);
}

} // namespace noise
} // namespace bitchat
