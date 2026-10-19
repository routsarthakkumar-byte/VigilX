#ifndef USER_HPP
#define USER_HPP

#include <string>

enum class Role { GUEST, EMPLOYEE, SECURITY_ANALYST, ADMIN };

class User {
protected:
    std::string username_;
    std::string passwordHash_;
    Role role_;
    int failedAttempts_;
    bool accountLocked_;

public:
    User(std::string uname, std::string pwdHash, Role role)
        : username_(std::move(uname)), passwordHash_(std::move(pwdHash)), 
          role_(role), failedAttempts_(0), accountLocked_(false) {}

    virtual ~User() = default;

    std::string getUsername() const { return username_; }
    Role getRole() const { return role_; }
    int getFailedAttempts() const { return failedAttempts_; }
    bool isLocked() const { return accountLocked_; }

    void incrementFailedAttempts() {
        failedAttempts_++;
        if (failedAttempts_ >= 5) {
            accountLocked_ = true;
        }
    }

    void resetFailedAttempts() { failedAttempts_ = 0; }
    void setLocked(bool locked) { accountLocked_ = locked; }

    virtual std::string getRoleName() const = 0;
};

class Admin : public User {
public:
    Admin(std::string uname, std::string pwdHash) : User(std::move(uname), std::move(pwdHash), Role::ADMIN) {}
    std::string getRoleName() const override { return "ADMIN"; }
};

class Employee : public User {
public:
    Employee(std::string uname, std::string pwdHash) : User(std::move(uname), std::move(pwdHash), Role::EMPLOYEE) {}
    std::string getRoleName() const override { return "EMPLOYEE"; }
};

class Guest : public User {
public:
    Guest(std::string uname, std::string pwdHash) : User(std::move(uname), std::move(pwdHash), Role::GUEST) {}
    std::string getRoleName() const override { return "GUEST"; }
};

class SecurityAnalyst : public User {
public:
    SecurityAnalyst(std::string uname, std::string pwdHash) : User(std::move(uname), std::move(pwdHash), Role::SECURITY_ANALYST) {}
    std::string getRoleName() const override { return "SECURITY_ANALYST"; }
};

#endif // USER_HPP