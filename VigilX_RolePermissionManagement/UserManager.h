#pragma once
#include <vector>
#include <memory>
#include <string>
#include "User.h"
class SecurityLogger;
class UserManager {
private:
    std::vector<std::unique_ptr<User>> users;
    int nextUserID=1;
    SecurityLogger& logger;
    const std::string filename="users.txt";
    void saveUsers() const;
    void loadUsers();
public:
    explicit UserManager(SecurityLogger& securityLogger);
    User* findUserByID(int id) const;
    void saveChanges() const;
    void addUser(); void viewUsers() const; void searchUser() const; void deleteUser();
    void unlockUserAccount();
    void changeUserRole();
};
