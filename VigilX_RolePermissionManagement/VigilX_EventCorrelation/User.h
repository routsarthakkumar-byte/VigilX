#pragma once
#include <string>
class User {
private:
    int userID;
    std::string username;
    bool active;
    std::string passwordSalt;
    std::string passwordHash;
    int failedAttempts;
    bool locked;
    bool mustChangePassword;
public:
    User(int id, const std::string& name);
    virtual ~User() = default;
    int getUserID() const;
    std::string getUsername() const;
    bool isActive() const;
    void deactivate();
    bool isLocked() const;
    int getFailedAttempts() const;
    bool needsPasswordSetup() const;
    void setPassword(const std::string& password);
    bool verifyPassword(const std::string& password) const;
    void loadPasswordData(const std::string& salt, const std::string& hash, int attempts, bool isLocked, bool needsChange);
    void recordFailedAttempt();
    void resetFailedAttempts();
    void unlockAccount();
    std::string getPasswordSalt() const;
    std::string getPasswordHash() const;
    bool getMustChangePassword() const;
    virtual std::string getRole() const = 0;
    virtual void displayPermissions() const = 0;
    void display() const;
};
class Admin : public User {
public: Admin(int id, const std::string& name); std::string getRole() const override; void displayPermissions() const override;
};
class Employee : public User {
public: Employee(int id, const std::string& name); std::string getRole() const override; void displayPermissions() const override;
};
class Guest : public User {
public: Guest(int id, const std::string& name); std::string getRole() const override; void displayPermissions() const override;
};
