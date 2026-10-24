#include "auth_foundation.h"

#include <iostream>
#include <string>

int main() {
    using namespace VigilXAuth;

    std::string salt;
    std::string hash;
    std::string token1;
    std::string token2;

    if (!generateRandomHex(16, salt)) {
        std::cerr << "FAIL: Salt generation\n";
        return 1;
    }

    if (!hashPassword("TestPassword123!", salt, hash)) {
        std::cerr << "FAIL: Password hashing\n";
        return 1;
    }

    if (!verifyPassword("TestPassword123!", salt, hash)) {
        std::cerr << "FAIL: Correct password verification\n";
        return 1;
    }

    if (verifyPassword("WrongPassword123!", salt, hash)) {
        std::cerr << "FAIL: Incorrect password was accepted\n";
        return 1;
    }

    if (!generateSessionToken(token1) ||
        !generateSessionToken(token2)) {
        std::cerr << "FAIL: Session token generation\n";
        return 1;
    }

    if (token1.size() != 64 || token1 == token2) {
        std::cerr << "FAIL: Session token validation\n";
        return 1;
    }

    std::cout << "PASS: Secure salt generation\n";
    std::cout << "PASS: PBKDF2 password hashing\n";
    std::cout << "PASS: Correct password accepted\n";
    std::cout << "PASS: Incorrect password rejected\n";
    std::cout << "PASS: Unique 256-bit session tokens\n";

    return 0;
}
