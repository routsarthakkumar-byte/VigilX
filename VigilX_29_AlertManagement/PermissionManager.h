#pragma once
#include <string>
#include <vector>
class User;
class UserManager;
class ResourceManager;
class Resource;
class SecurityLogger;
class PermissionManager {
private:
    struct Rule { std::string username; int resourceID; std::string action; bool allowed; };
    std::vector<Rule> rules;
    const std::string filename = "permissions.txt";
    SecurityLogger& logger;
    void loadRules();
    void saveRules() const;
public:
    explicit PermissionManager(SecurityLogger& securityLogger);
    bool isAllowed(const User& user, const Resource& resource, const std::string& action) const;
    void runMenu(const User& admin, const UserManager& users, const ResourceManager& resources);
};
