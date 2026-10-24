#include "auth_session.h"

#include <chrono>
#include <iostream>
#include <string>
#include <thread>

int main() {
    using namespace VigilXAuth;

    SessionManager manager(std::chrono::seconds(2));

    std::string token;

    if (!manager.create("test_employee", "Employee", token)) {
        std::cerr << "FAIL: Session creation\n";
        return 1;
    }

    if (token.size() != 64) {
        std::cerr << "FAIL: Token length\n";
        return 1;
    }
    std::cout << "PASS: Secure session token created\n";

    Session session;

    if (!manager.get(token, session) ||
        session.username != "test_employee" ||
        session.role != "Employee") {
        std::cerr << "FAIL: Session lookup\n";
        return 1;
    }
    std::cout << "PASS: Session identity lookup\n";

    if (manager.create("test_admin", "UnknownRole", token)) {
        std::cerr << "FAIL: Invalid role accepted\n";
        return 1;
    }
    std::cout << "PASS: Invalid role rejected\n";

    std::string expiringToken;

    if (!manager.create("temporary_user", "Guest", expiringToken)) {
        std::cerr << "FAIL: Temporary session creation\n";
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::seconds(3));

    if (manager.get(expiringToken, session)) {
        std::cerr << "FAIL: Expired session accepted\n";
        return 1;
    }
    std::cout << "PASS: Expired session rejected\n";

    if (!manager.remove(token)) {
        std::cerr << "FAIL: Session logout\n";
        return 1;
    }

    if (manager.get(token, session)) {
        std::cerr << "FAIL: Removed session still valid\n";
        return 1;
    }
    std::cout << "PASS: Logout invalidates session\n";

    return 0;
}
