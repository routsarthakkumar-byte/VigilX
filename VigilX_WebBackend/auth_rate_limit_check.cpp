#include <chrono>
#include <iostream>
#include <map>
#include <mutex>
#include <string>

using namespace std;

struct LoginAttemptState {
    int failedAttempts = 0;
    chrono::steady_clock::time_point lockedUntil{};
};

mutex loginAttemptMutex;
map<string, LoginAttemptState> loginAttempts;

bool isLoginLocked(const string& username) {
    lock_guard<mutex> lock(loginAttemptMutex);

    auto it = loginAttempts.find(username);
    if (it == loginAttempts.end()) {
        return false;
    }

    const auto now = chrono::steady_clock::now();
    const auto noLock = chrono::steady_clock::time_point{};

    if (it->second.lockedUntil == noLock) {
        return false;
    }

    if (now >= it->second.lockedUntil) {
        it->second.failedAttempts = 0;
        it->second.lockedUntil = noLock;
        return false;
    }

    return true;
}

void recordFailedLogin(const string& username) {
    lock_guard<mutex> lock(loginAttemptMutex);

    auto& state = loginAttempts[username];

    if (chrono::steady_clock::now() < state.lockedUntil) {
        return;
    }

    ++state.failedAttempts;

    if (state.failedAttempts >= 5) {
        state.lockedUntil =
            chrono::steady_clock::now() + chrono::minutes(15);
    }
}

void resetLoginAttempts(const string& username) {
    lock_guard<mutex> lock(loginAttemptMutex);
    loginAttempts.erase(username);
}

int main() {
    const string username = "rate_limit_test_user";

    for (int i = 0; i < 4; ++i) {
        recordFailedLogin(username);
    }

    if (isLoginLocked(username)) {
        cerr << "FAIL: Locked before the fifth failure.\n";
        return 1;
    }
    cout << "PASS: First four failures do not lock the account.\n";

    recordFailedLogin(username);

    if (!isLoginLocked(username)) {
        cerr << "FAIL: Fifth failure did not lock the account.\n";
        return 1;
    }
    cout << "PASS: Fifth failure locks the account.\n";

    recordFailedLogin(username);

    if (!isLoginLocked(username)) {
        cerr << "FAIL: Lockout was unexpectedly cleared.\n";
        return 1;
    }
    cout << "PASS: Extra failure preserves the active lockout.\n";

    resetLoginAttempts(username);

    if (isLoginLocked(username)) {
        cerr << "FAIL: Reset did not clear the lockout.\n";
        return 1;
    }
    cout << "PASS: Reset clears the lockout.\n";

    return 0;
}
