#pragma once

#include <filesystem>
#include <system_error>

#include <fstream>
#include <map>
#include <mutex>
#include <string>

namespace VigilXAuth {

inline std::string trimField(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }

    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

struct Credential {
    std::string username;
    std::string role;
    std::string salt;
    std::string passwordHash;
};

class CredentialStore {
private:
    std::string filename;
    std::mutex storeMutex;

    bool loadUnlocked(std::map<std::string, Credential>& credentials) {
        credentials.clear();

        std::error_code filesystemError;
        const bool fileExists =
            std::filesystem::exists(filename, filesystemError);

        if (filesystemError) {
            return false;
        }

        if (!fileExists) {
            return true;
        }

        std::ifstream input(filename);

        if (!input.is_open()) {
            return false;
        }

        std::string line;

        while (std::getline(input, line)) {
            if (line.empty()) {
                continue;
            }

            const std::size_t p1 = line.find('|');
            if (p1 == std::string::npos) {
                return false;
            }

            const std::size_t p2 = line.find('|', p1 + 1);
            if (p2 == std::string::npos) {
                return false;
            }

            const std::size_t p3 = line.find('|', p2 + 1);
            if (p3 == std::string::npos) {
                return false;
            }

            Credential c;
            c.username = trimField(line.substr(0, p1));
            c.role = trimField(line.substr(p1 + 1, p2 - p1 - 1));
            c.salt = trimField(line.substr(p2 + 1, p3 - p2 - 1));
            c.passwordHash = trimField(line.substr(p3 + 1));

            if (c.username.empty() ||
                (c.role != "Admin" &&
                 c.role != "Employee" &&
                 c.role != "Guest") ||
                c.salt.size() != 32 ||
                c.passwordHash.size() != 64) {
                return false;
            }

            if (!credentials.emplace(c.username, c).second) {
                return false;
            }
        }

        return input.eof() && !input.bad();
    }

    bool validCredential(const Credential& c) const {
        return !c.username.empty() &&
               c.username.find('|') == std::string::npos &&
               c.username.find('\n') == std::string::npos &&
               c.username.find('\r') == std::string::npos &&
               (c.role == "Admin" ||
                c.role == "Employee" ||
                c.role == "Guest") &&
               c.salt.size() == 32 &&
               c.passwordHash.size() == 64 &&
               c.salt.find_first_not_of("0123456789abcdefABCDEF")
                   == std::string::npos &&
               c.passwordHash.find_first_not_of("0123456789abcdefABCDEF")
                   == std::string::npos;
    }

    bool appendUnlocked(const Credential& c) {
        std::ofstream output(filename, std::ios::app);

        if (!output.is_open()) {
            return false;
        }

        output << c.username << " | "
               << c.role << " | "
               << c.salt << " | "
               << c.passwordHash << '\n';

        output.flush();
        return output.good();
    }

public:
    explicit CredentialStore(
        const std::string& file = "../credentials.txt"
    ) : filename(file) {}

    bool load(std::map<std::string, Credential>& credentials) {
        std::lock_guard<std::mutex> lock(storeMutex);
        return loadUnlocked(credentials);
    }

    bool save(const Credential& credential) {
        std::lock_guard<std::mutex> lock(storeMutex);

        if (!validCredential(credential)) {
            return false;
        }

        std::map<std::string, Credential> credentials;

        if (!loadUnlocked(credentials)) {
            return false;
        }

        if (credentials.find(credential.username) != credentials.end()) {
            return false;
        }

        return appendUnlocked(credential);
    }

    bool createIfAbsent(const Credential& credential) {
        std::lock_guard<std::mutex> lock(storeMutex);

        if (!validCredential(credential)) {
            return false;
        }

        std::map<std::string, Credential> credentials;

        if (!loadUnlocked(credentials)) {
            return false;
        }

        if (credentials.find(credential.username) != credentials.end()) {
            return false;
        }

        return appendUnlocked(credential);
    }
};

} // namespace VigilXAuth
