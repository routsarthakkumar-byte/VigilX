#include "auth_validation.h"
#include <iostream>

int main() {
    using nlohmann::json;
    std::string username, password, role;

    json validSignup = {
        {"username", "test_employee"},
        {"password", "safe-test-password"},
        {"role", "Employee"}
    };

    if (!VigilXAuth::validSignupRequest(
            validSignup, username, password, role)) {
        std::cerr << "FAIL: Valid signup rejected\n";
        return 1;
    }
    std::cout << "PASS: Valid signup accepted\n";

    json adminSignup = {
        {"username", "test_admin"},
        {"password", "safe-test-password"},
        {"role", "Admin"}
    };

    if (VigilXAuth::validSignupRequest(
            adminSignup, username, password, role)) {
        std::cerr << "FAIL: Public Admin signup accepted\n";
        return 1;
    }
    std::cout << "PASS: Public Admin signup rejected\n";

    json shortPassword = {
        {"username", "test_user"},
        {"password", "123",
         },
        {"role", "Guest"}
    };

    if (VigilXAuth::validSignupRequest(
            shortPassword, username, password, role)) {
        std::cerr << "FAIL: Short password accepted\n";
        return 1;
    }
    std::cout << "PASS: Short signup password rejected\n";

    json validLogin = {
        {"username", "test_employee"},
        {"password", "safe-test-password"}
    };

    if (!VigilXAuth::validLoginRequest(
            validLogin, username, password)) {
        std::cerr << "FAIL: Valid login request rejected\n";
        return 1;
    }
    std::cout << "PASS: Valid login request accepted\n";

    json missingPassword = {
        {"username", "test_employee"}
    };

    if (VigilXAuth::validLoginRequest(
            missingPassword, username, password)) {
        std::cerr << "FAIL: Login without password accepted\n";
        return 1;
    }
    std::cout << "PASS: Login without password rejected\n";

    return 0;
}
