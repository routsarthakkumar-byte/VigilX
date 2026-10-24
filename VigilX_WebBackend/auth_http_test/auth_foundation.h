#pragma once

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace VigilXAuth {

inline std::string toHex(const unsigned char* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (std::size_t i = 0; i < size; ++i) {
        output << std::setw(2) << static_cast<unsigned int>(data[i]);
    }

    return output.str();
}

inline bool generateRandomHex(std::size_t byteCount, std::string& output) {
    if (byteCount == 0 || byteCount > 1024) {
        return false;
    }

    std::vector<unsigned char> bytes(byteCount);

    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        return false;
    }

    output = toHex(bytes.data(), bytes.size());
    return true;
}

inline bool hashPassword(
    const std::string& password,
    const std::string& saltHex,
    std::string& hashHex
) {
    if (password.empty() || saltHex.size() != 32) {
        return false;
    }

    std::vector<unsigned char> salt(16);

    for (std::size_t i = 0; i < salt.size(); ++i) {
        auto hexValue = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

        int high = hexValue(saltHex[i * 2]);
        int low = hexValue(saltHex[i * 2 + 1]);

        if (high < 0 || low < 0) {
            return false;
        }

        salt[i] = static_cast<unsigned char>((high << 4) | low);
    }

    unsigned char hash[32];

    if (PKCS5_PBKDF2_HMAC(
            password.c_str(),
            static_cast<int>(password.size()),
            salt.data(),
            static_cast<int>(salt.size()),
            600000,
            EVP_sha256(),
            sizeof(hash),
            hash
        ) != 1) {
        return false;
    }

    hashHex = toHex(hash, sizeof(hash));
    OPENSSL_cleanse(hash, sizeof(hash));
    return true;
}

inline bool verifyPassword(
    const std::string& password,
    const std::string& saltHex,
    const std::string& expectedHashHex
) {
    if (expectedHashHex.size() != 64) {
        return false;
    }

    std::string actualHash;

    if (!hashPassword(password, saltHex, actualHash)) {
        return false;
    }

    return CRYPTO_memcmp(
        actualHash.data(),
        expectedHashHex.data(),
        expectedHashHex.size()
    ) == 0;
}

inline bool generateSessionToken(std::string& token) {
    return generateRandomHex(32, token);
}

} // namespace VigilXAuth
