#include <nlohmann/json.hpp>
#include <iostream>
#include <string>

int main() {
    nlohmann::json request = {
        {"username", "test_employee"},
        {"password", "test-password"},
        {"role", "Employee"}
    };

    std::string body = request.dump();
    auto parsed = nlohmann::json::parse(body);

    if (parsed.value("username", std::string()) != "test_employee") {
        std::cerr << "FAIL: JSON parsing\n";
        return 1;
    }

    std::cout << "PASS: JSON request creation\n";
    std::cout << "PASS: JSON request parsing\n";
    std::cout << "PASS: Username field extraction\n";
    return 0;
}
