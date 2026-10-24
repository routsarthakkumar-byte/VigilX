#include "auth_foundation.h"
#include "auth_storage.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

int main() {
    const std::string username = "AdminTest";
    const std::string password = "VigilXAdminTest@2026";

    const std::string dataDir = "./test_data/";
    const std::string credentialsFile = dataDir + "credentials.txt";
    const std::string usersFile = dataDir + "users.txt";

    if (!std::filesystem::exists(dataDir)) {
        std::cerr << "Test data directory not found.\n";
        return 1;
    }

    VigilXAuth::CredentialStore store(credentialsFile);
    std::map<std::string, VigilXAuth::Credential> credentials;

    if (!store.load(credentials)) {
        std::cerr << "Could not read credentials file.\n";
        return 1;
    }

    if (credentials.find(username) != credentials.end()) {
        std::cout << "AdminTest already exists in credentials.\n";
        return 0;
    }

    std::string salt;
    std::string passwordHash;

    if (!VigilXAuth::generateRandomHex(16, salt) ||
        !VigilXAuth::hashPassword(password, salt, passwordHash)) {
        std::cerr << "Password hashing failed.\n";
        return 1;
    }

    std::ifstream existingUsers(usersFile);
    if (!existingUsers.is_open()) {
        std::cerr << "Could not read users file.\n";
        return 1;
    }

    std::string line;
    int nextId = 1;

    while (std::getline(existingUsers, line)) {
        if (line.empty()) {
            continue;
        }

        const auto separator = line.find('|');
        if (separator != std::string::npos) {
            try {
                int id = std::stoi(line.substr(0, separator));
                if (id >= nextId) {
                    nextId = id + 1;
                }
            } catch (...) {
                std::cerr << "Invalid user record found.\n";
                return 1;
            }
        }
    }
    existingUsers.close();

    VigilXAuth::Credential credential{
        username, "Admin", salt, passwordHash
    };

    if (!store.createIfAbsent(credential)) {
        std::cerr << "Could not save AdminTest credentials.\n";
        return 1;
    }

    std::ofstream users(usersFile, std::ios::app);
    if (!users.is_open()) {
        std::cerr << "Credentials saved, but users file could not be opened.\n";
        return 1;
    }

    users << nextId << " | Admin | " << username << '\n';
    users.close();

    if (!users.good()) {
        std::cerr << "Could not finish writing the users file.\n";
        return 1;
    }

    std::cout << "Admin test account created successfully.\n";
    std::cout << "Username: " << username << '\n';
    std::cout << "Password: " << password << '\n';
    std::cout << "Scope: isolated auth_http_test data only.\n";

    return 0;
}
