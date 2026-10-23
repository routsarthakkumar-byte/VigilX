#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>

int main() {
    unsigned char randomBytes[32];
    unsigned char hash[32];
    const unsigned char password[] = "VigilX-Test-Password";
    unsigned char salt[16] = {};

    if (RAND_bytes(randomBytes, sizeof(randomBytes)) != 1) {
        return 1;
    }

    if (PKCS5_PBKDF2_HMAC(
            reinterpret_cast<const char*>(password),
            sizeof(password) - 1,
            salt,
            sizeof(salt),
            100000,
            EVP_sha256(),
            sizeof(hash),
            hash) != 1) {
        return 2;
    }

    std::cout << "OpenSSL hashing and secure random test passed.\n";
    return 0;
}
