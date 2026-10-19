#pragma once
#include <string>
#include "SecurityLogger.h"

class Threat {
protected:
    SecurityLogger& logger;
    std::string readTargetUsername() const;
    std::string readTargetResource() const;
public:
    explicit Threat(SecurityLogger& securityLogger);
    virtual ~Threat() = default;
    virtual std::string getName() const = 0;
    virtual std::string getSeverity() const = 0;
    virtual void simulate() = 0;
};

class BruteForceAttack : public Threat {
public:
    explicit BruteForceAttack(SecurityLogger&); std::string getName() const override;
    std::string getSeverity() const override; void simulate() override;
};
class UnauthorizedAccess : public Threat {
public:
    explicit UnauthorizedAccess(SecurityLogger&); std::string getName() const override;
    std::string getSeverity() const override; void simulate() override;
};
class SuspiciousLogin : public Threat {
public:
    explicit SuspiciousLogin(SecurityLogger&); std::string getName() const override;
    std::string getSeverity() const override; void simulate() override;
};
class PrivilegeEscalation : public Threat {
public:
    explicit PrivilegeEscalation(SecurityLogger&); std::string getName() const override;
    std::string getSeverity() const override; void simulate() override;
};
class AbnormalResourceAccess : public Threat {
public:
    explicit AbnormalResourceAccess(SecurityLogger&); std::string getName() const override;
    std::string getSeverity() const override; void simulate() override;
};
class CustomThreatScenario : public Threat {
public:
    explicit CustomThreatScenario(SecurityLogger&); std::string getName() const override;
    std::string getSeverity() const override; void simulate() override;
};
