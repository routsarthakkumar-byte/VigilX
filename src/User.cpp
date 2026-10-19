#include "User.h"
#include "Exceptions.h"
#include <functional>

User::User(const std::string& id, const std::string& username, const std::string& plainPassword)
    : id_(id), username_(username) {
    if (username.empty())           throw InvalidInputException("username cannot be empty");
    if (plainPassword.size() < 4)   throw InvalidInputException("password must be at least 4 characters");
    // plain password is hashed immediately and NEVER stored
    passwordHash_ = hashPassword(username, plainPassword);
}

// Simulation-grade salted hash. Fine for a class project; real systems use bcrypt/argon2.
std::string User::hashPassword(const std::string& salt, const std::string& plain) {
    return std::to_string(std::hash<std::string>{}("vx$" + salt + "$" + plain));
}

bool User::authenticate(const std::string& plainPassword) {
    if (locked_) throw AccountLockedException(username_);

    if (hashPassword(username_, plainPassword) == passwordHash_) {
        failedAttempts_ = 0;            // success resets the counter
        return true;
    }
    ++failedAttempts_;
    if (failedAttempts_ >= MAX_FAILED_ATTEMPTS) locked_ = true;
    return false;
}

void User::unlock() {
    locked_ = false;
    failedAttempts_ = 0;
}

std::string User::describe() const {
    return "[" + id_ + "] " + username_ + " (" + toString(role()) + ", clearance " +
           std::to_string(clearance()) + ")" + (locked_ ? " [LOCKED]" : "");
}

std::ostream& operator<<(std::ostream& os, const User& u) {
    return os << u.describe();
}
