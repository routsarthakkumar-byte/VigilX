#include <windows.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "auth_foundation.h"
#include "auth_storage.h"

int main() {
    const std::string filePath = "test_data/credentials.txt";
    const std::string backupPath =
        "test_data/credentials.pre_admin_reset.bak";
    const std::string tempPath = "test_data/credentials.txt.tmp";

    const std::string target = "AdminAuthCheck2026";
    const std::string password = "VigilXAdminAuthCheck2026@2026";

    std::ifstream backup(backupPath, std::ios::binary);
    if (!backup) {
        std::cerr << "ERROR: Backup missing; stopping.\n";
        return 1;
    }
    backup.close();

    std::map<std::string, VigilXAuth::Credential> credentials;
    VigilXAuth::CredentialStore store(filePath);

    if (!store.load(credentials)) {
        std::cerr << "ERROR: Credential file validation failed.\n";
        return 2;
    }

    auto it = credentials.find(target);
    if (it == credentials.end() || it->second.role != "Admin") {
        std::cerr << "ERROR: Expected isolated Admin account not found.\n";
        return 3;
    }

    std::string salt;
    if (!VigilXAuth::generateRandomHex(16, salt)) {
        std::cerr << "ERROR: Salt generation failed.\n";
        return 4;
    }

    std::string hash;
    if (!VigilXAuth::hashPassword(password, salt, hash)) {
        std::cerr << "ERROR: Password hashing failed.\n";
        return 5;
    }

    it->second.salt = salt;
    it->second.passwordHash = hash;

    std::ofstream output(tempPath, std::ios::binary | std::ios::trunc);
    if (!output) {
        std::cerr << "ERROR: Cannot create temporary file.\n";
        return 6;
    }

    for (const auto& entry : credentials) {
        const auto& c = entry.second;
        output << c.username << " | "
               << c.role << " | "
               << c.salt << " | "
               << c.passwordHash << '\n';
    }

    output.flush();
    if (!output.good()) {
        output.close();
        std::cerr << "ERROR: Temporary file write failed.\n";
        return 7;
    }
    output.close();

    if (!MoveFileExA(
            tempPath.c_str(),
            filePath.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::cerr << "ERROR: Windows file replacement failed ("
                  << GetLastError() << ").\n";
        return 8;
    }

    std::cout << "SUCCESS: Isolated Admin test credential reset.\n";
    std::cout << "Credential count: " << credentials.size() << "\n";
    std::cout << "Backup preserved.\n";
    return 0;
}
