#ifndef RESOURCE_HPP
#define RESOURCE_HPP

#include <string>
#include "User.hpp" // Added to resolve the Role enum definition

enum class SensitivityLevel { LOW = 1, MEDIUM = 2, HIGH = 3, CRITICAL = 4 };

class Resource {
protected:
    std::string resourceId_;
    std::string name_;
    SensitivityLevel sensitivity_;
    Role minimumRequiredRole_;

public:
    Resource(std::string id, std::string name, SensitivityLevel sens, Role minRole)
        : resourceId_(std::move(id)), name_(std::move(name)), sensitivity_(sens), minimumRequiredRole_(minRole) {}

    virtual ~Resource() = default;

    std::string getId() const { return resourceId_; }
    std::string getName() const { return name_; }
    SensitivityLevel getSensitivity() const { return sensitivity_; }
    Role getMinimumRequiredRole() const { return minimumRequiredRole_; }

    virtual std::string getResourceType() const = 0;
};

class DatabaseResource : public Resource {
public:
    DatabaseResource(std::string id, std::string name, SensitivityLevel sens, Role minRole)
        : Resource(std::move(id), std::move(name), sens, minRole) {}
    std::string getResourceType() const override { return "DATABASE"; }
};

class AdminPanelResource : public Resource {
public:
    AdminPanelResource(std::string id, std::string name, SensitivityLevel sens, Role minRole)
        : Resource(std::move(id), std::move(name), sens, minRole) {}
    std::string getResourceType() const override { return "ADMIN_PANEL"; }
};

#endif // RESOURCE_HPP