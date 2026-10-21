#pragma once
#include "SecurityLogger.h"
#include <string>
#include <vector>

struct SecurityPolicy {
    int id;
    std::string name;
    std::string description;
    bool enabled;
};

struct PolicyFinding {
    int policyID;
    std::string policyName;
    std::string status;
    std::string details;
    std::string recommendation;
};

class SecurityPolicyEngine {
private:
    SecurityLogger& logger;
    const std::string policyFile = "policies.txt";
    const std::string auditFile = "compliance_audit.txt";
    const std::string csvFile = "compliance_audit.csv";
    std::vector<SecurityPolicy> policies;
    void loadPolicies();
    void savePolicies() const;
    std::vector<PolicyFinding> evaluatePolicies() const;
    void exportAudit(const std::vector<PolicyFinding>& findings, const std::string& timestamp) const;
public:
    explicit SecurityPolicyEngine(SecurityLogger& securityLogger);
    void runMenu(const std::string& username, const std::string& role);
};
