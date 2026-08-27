#include "neta/crypto.hpp"

#include <openssl/evp.h>

#include <array>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

namespace neta {

std::string sha256_hex(std::string_view input) {
    using CtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    CtxPtr ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx.get(), input.data(), input.size()) != 1) {
        throw std::runtime_error("SHA-256 initialization/update failed");
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &length) != 1) {
        throw std::runtime_error("SHA-256 finalization failed");
    }

    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < length; ++i) {
        out << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }
    return out.str();
}

} // namespace neta
