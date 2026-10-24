#ifndef AUTH_VALIDATION_H
#define AUTH_VALIDATION_H

#include <string>
#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>

namespace VigilXAuth {

inline std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }

    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

inline bool validUsername(const std::string& username) {
    if (username.size() < 3 || username.size() > 32) {
        return false;
    }

    return std::all_of(username.begin(), username.end(),
        [](unsigned char ch) {
            return std::isalnum(ch) || ch == '_' || ch == '-';
        });
}

inline bool validPassword(const std::string& password) {
    return password.size() >= 8 && password.size() <= 128;
}

inline bool validSignupRequest(
    const nlohmann::json& body,
    std::string& username,
    std::string& password,
    std::string& role
) {
    if (!body.is_object()) {
        return false;
    }

    if (!body.contains("username") || !body["username"].is_string() ||
        !body.contains("password") || !body["password"].is_string() ||
        !body.contains("role") || !body["role"].is_string()) {
        return false;
    }

    username = trim(body["username"].get<std::string>());
    password = body["password"].get<std::string>();
    role = body["role"].get<std::string>();

    if (!validUsername(username) || !validPassword(password)) {
        return false;
    }

    return role == "Employee" || role == "Guest";
}

inline bool validLoginRequest(
    const nlohmann::json& body,
    std::string& username,
    std::string& password
) {
    if (!body.is_object()) {
        return false;
    }

    if (!body.contains("username") || !body["username"].is_string() ||
        !body.contains("password") || !body["password"].is_string()) {
        return false;
    }

    username = trim(body["username"].get<std::string>());
    password = body["password"].get<std::string>();

    return validUsername(username) &&
           !password.empty() &&
           password.size() <= 128;
}

}

#endif
