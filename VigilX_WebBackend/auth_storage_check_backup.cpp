#include "auth_storage.h"

#include <iostream>
#include <map>
#include <string>

int main() {
    using namespace VigilXAuth;

    CredentialStore store("auth_storage_test_data.txt");
    std::map<std::string, Credential> credentials;

    if (!store.load(credentials)) {
        std::cerr << "FAIL: Empty store loading\n";
        return 1;
    }

    if (!credentials.empty()) {
        std::cerr << "FAIL: Unexpected test credentials\n";
        return 1;
    }

    Credential test;
    test.username = "test_employee";
    test.role = "Employee";
    test.salt = "0123456789abcdef0123456789abcdef";
    test.passwordHash = std::string(64, 'a');

    if (!store.save(test)) {
        std::cerr << "FAIL: Credential save\n";
        return 1;
    }

    if (!store.load(credentials)) {
        std::cerr << "FAIL: Credential reload returned false\n";
        return 1;
    }

    std::cerr << "Loaded credential count: " << credentials.size() << "\n";
    for (const auto& entry : credentials) {
        std::cerr << "Loaded key: [" << entry.first << "]\n";
    }

    auto found = credentials.find("test_employee");

    if (found == credentials.end()) {
        std::cerr << "FAIL: Username not found after reload\n";
        return 1;
    }

    std::cerr << "Loaded username: [" << found->second.username << "]\n";
    std::cerr << "Loaded role: [" << found->second.role << "]\n";
    std::cerr << "Loaded salt length: " << found->second.salt.size() << "\n";
    std::cerr << "Loaded hash length: " << found->second.passwordHash.size() << "\n";
    std::cerr << "Role matches: " << (found->second.role == test.role) << "\n";
    std::cerr << "Salt matches: " << (found->second.salt == test.salt) << "\n";
    std::cerr << "Hash matches: " << (found->second.passwordHash == test.passwordHash) << "\n";

    if (found->second.role != test.role ||
        found->second.salt != test.salt ||
        found->second.passwordHash != test.passwordHash) {
        std::cerr << "FAIL: Credential data verification\n";
        return 1;
    }

    std::cout << "PASS: Empty credential store loads\n";
    std::cout << "PASS: Credential record saves\n";
    std::cout << "PASS: Credential record reloads correctly\n";

    return 0;
}
