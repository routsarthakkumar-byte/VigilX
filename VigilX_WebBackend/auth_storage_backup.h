#pragma once

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

public:
    explicit CredentialStore(
        const std::string& file = "../credentials.txt"
    ) : filename(file) {}

    bool load(std::map<std::string, Credential>& credentials) {
        std::lock_guard<std::mutex> lock(storeMutex);
        credentials.clear();

        std::ifstream input(filename);
        if (!input.is_open()) {
            return true;
        }

        std::string line;

        while (std::getline(input, line)) {
            if (line.empty()) {
                continue;
            }

            std::size_t p1 = line.find('|');
            if (p1 == std::string::npos) {
                return false;
            }

            std::size_t p2 = line.find('|', p1 + 1);
            if (p2 == std::string::npos) {
                return false;
            }

            std::size_t p3 = line.find('|', p2 + 1);
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

        return !input.bad();
    }

    bool save(const Credential& credential) {
        std::lock_guard<std::mutex> lock(storeMutex);

        std::ofstream output(filename, std::ios::app);
        if (!output.is_open()) {
            return false;
        }

        output << credential.username << " | "
               << credential.role << " | "
               << credential.salt << " | "
               << credential.passwordHash << '\n';

        output.flush();
        return output.good();
    }
};

} // namespace VigilXAuth
