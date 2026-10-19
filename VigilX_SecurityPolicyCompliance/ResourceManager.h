#pragma once
#include <vector>
#include <string>
#include "Resource.h"
#include "RiskScoringEngine.h"
class SecurityLogger;
class PermissionManager;
class ResourceManager {
private:
    std::vector<Resource> resources; int nextResourceID=1; SecurityLogger& logger; RiskScoringEngine riskEngine; const std::string filename="resources.txt";
    void saveResources() const; void loadResources();
public:
    explicit ResourceManager(SecurityLogger& securityLogger);
    const Resource* findResourceByID(int id) const;
    void addResource(); void viewResources() const; void searchResource() const; void deleteResource(); void requestAccess(const User& user, const PermissionManager& permissions) const;
};
