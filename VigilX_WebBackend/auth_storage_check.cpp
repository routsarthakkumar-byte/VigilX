#include "auth_storage.h"

#include <iostream>
#include <map>
#include <string>
#include <cstdio>

int main() {
    using namespace VigilXAuth;

    std::remove("auth_storage_test_data.txt");

    CredentialStore store("auth_storage_test_data.txt");
    std::map<std::string, Credential> credentials;

    if (!store.load(credentials) || !credentials.empty()) {
        std::cerr << "FAIL: Empty credential store loads\n";
        return 1;
    }
    std::cout << "PASS: Empty credential store loads\n";

    Credential test;
    test.username = "test_employee";
    test.role = "Employee";
    test.salt = "0123456789abcdef0123456789abcdef";
    test.passwordHash = std::string(64, 'a');

    if (!store.save(test)) {
        std::cerr << "FAIL: Credential record saves\n";
        return 1;
    }
    std::cout << "PASS: Credential record saves\n";

    if (store.save(test)) {
        std::cerr << "FAIL: Duplicate username was saved\n";
        return 1;
    }
    std::cout << "PASS: Duplicate username rejected\n";

    if (!store.load(credentials)) {
        std::cerr << "FAIL: Credential reload\n";
        return 1;
    }

    auto found = credentials.find("test_employee");

    if (found == credentials.end() ||
        found->second.role != test.role ||
        found->second.salt != test.salt ||
        found->second.passwordHash != test.passwordHash ||
        credentials.size() != 1) {
        std::cerr << "FAIL: Credential reload verification\n";
        return 1;
    }
    std::cout << "PASS: Credential record reloads correctly\n";

    Credential invalid;
    invalid.username = "invalid_user";
    invalid.role = "Admin";
    invalid.salt = "short";
    invalid.passwordHash = "invalid";

    if (store.save(invalid)) {
        std::cerr << "FAIL: Invalid credential was saved\n";
        return 1;
    }
    std::cout << "PASS: Invalid credential rejected\n";

    std::remove("auth_storage_test_data.txt");
    return 0;
}
