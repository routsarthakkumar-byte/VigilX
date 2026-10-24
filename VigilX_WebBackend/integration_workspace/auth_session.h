#pragma once

#include "auth_foundation.h"

#include <chrono>
#include <map>
#include <mutex>
#include <string>

namespace VigilXAuth {

struct Session {
    std::string username;
    std::string role;
    std::chrono::steady_clock::time_point expiresAt;
};

class SessionManager {
private:
    std::map<std::string, Session> sessions;
    std::mutex sessionMutex;
    std::chrono::seconds sessionLifetime;

public:
    explicit SessionManager(
        std::chrono::seconds lifetime = std::chrono::hours(1)
    ) : sessionLifetime(lifetime) {}

    bool create(
        const std::string& username,
        const std::string& role,
        std::string& token
    ) {
        if (username.empty() ||
            (role != "Admin" &&
             role != "Employee" &&
             role != "Guest") ||
            sessionLifetime.count() <= 0) {
            return false;
        }

        std::string newToken;

        if (!generateSessionToken(newToken)) {
            return false;
        }

        std::lock_guard<std::mutex> lock(sessionMutex);

        const auto now = std::chrono::steady_clock::now();

        for (auto it = sessions.begin(); it != sessions.end();) {
            if (it->second.expiresAt <= now) {
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }

        sessions.emplace(
            newToken,
            Session{username, role, now + sessionLifetime}
        );

        token = newToken;
        return true;
    }

    bool get(
        const std::string& token,
        Session& session
    ) {
        if (token.size() != 64) {
            return false;
        }

        std::lock_guard<std::mutex> lock(sessionMutex);

        auto it = sessions.find(token);

        if (it == sessions.end()) {
            return false;
        }

        if (it->second.expiresAt <= std::chrono::steady_clock::now()) {
            sessions.erase(it);
            return false;
        }

        session = it->second;
        return true;
    }

    bool remove(const std::string& token) {
        std::lock_guard<std::mutex> lock(sessionMutex);
        return sessions.erase(token) == 1;
    }

    std::size_t activeCount() {
        std::lock_guard<std::mutex> lock(sessionMutex);

        const auto now = std::chrono::steady_clock::now();

        for (auto it = sessions.begin(); it != sessions.end();) {
            if (it->second.expiresAt <= now) {
                it = sessions.erase(it);
            } else {
                ++it;
            }
        }

        return sessions.size();
    }
};

} // namespace VigilXAuth
