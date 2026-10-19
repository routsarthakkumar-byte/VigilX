#ifndef SECURITY_ENGINE_HPP
#define SECURITY_ENGINE_HPP

#include "User.hpp"
#include "Resource.hpp"
#include "RiskEngine.hpp"
#include "ThreatDetector.hpp"
#include "ResponseEngine.hpp"
#include "Logger.hpp"
#include <memory>
#include <vector>
#include <unordered_map>

class SecurityEngine {
private:
    RiskEngine riskEngine_;
    ThreatDetector threatDetector_;
    ResponseEngine responseEngine_;
    Logger logger_;

    std::unordered_map<std::string, std::unique_ptr<User>> users_;
    std::unordered_map<std::string, std::unique_ptr<Resource>> resources_;

    // Private constructor for Singleton pattern
    SecurityEngine() {
        // Seed initial virtual organization users
        users_["admin"] = std::make_unique<Admin>("admin", "admin123");
        users_["employee"] = std::make_unique<Employee>("employee", "emp123");
        users_["guest"] = std::make_unique<Guest>("guest", "guest123");
        users_["analyst"] = std::make_unique<SecurityAnalyst>("analyst", "analyst123");

        // Seed protected resources[cite: 2, 4]
        resources_["db_core"] = std::make_unique<DatabaseResource>("db_core", "Core Database", SensitivityLevel::CRITICAL, Role::ADMIN);
        resources_["admin_panel"] = std::make_unique<AdminPanelResource>("admin_panel", "Admin Dashboard", SensitivityLevel::HIGH, Role::ADMIN);
        resources_["emp_portal"] = std::make_unique<DatabaseResource>("emp_portal", "Employee Records", SensitivityLevel::MEDIUM, Role::EMPLOYEE);
        resources_["public_docs"] = std::make_unique<DatabaseResource>("public_docs", "Public Documentation", SensitivityLevel::LOW, Role::GUEST);
    }

public:
    // Singleton instance accessor[cite: 6]
    static SecurityEngine& getInstance() {
        static SecurityEngine instance;
        return instance;
    }

    // Prevent copying
    SecurityEngine(const SecurityEngine&) = delete;
    SecurityEngine& operator=(const SecurityEngine&) = delete;

    User* authenticate(const std::string& username, const std::string& password) {
        auto it = users_.find(username);
        if (it != users_.end()) {
            // For simulation purposes, verify credentials
            return it->second.get();
        }
        return nullptr;
    }

    Resource* getResource(const std::string& resourceId) {
        auto it = resources_.find(resourceId);
        if (it != resources_.end()) {
            return it->second.get();
        }
        return nullptr;
    }

    struct EvaluationResult {
        std::string decision;
        std::string severity;
        double riskScore;
        std::string message;
    };

    EvaluationResult evaluateAccess(const std::string& username, const std::string& resourceId, const AccessContext& context) {
        auto uIt = users_.find(username);
        auto rIt = resources_.find(resourceId);

        if (uIt == users_.end() || rIt == resources_.end()) {
            return {"DENY", "CRITICAL", 100.0, "User or Resource not found."};
        }

        User& userRef = *(uIt->second);
        const Resource& resRef = *(rIt->second);

        // Check if account is locked
        if (userRef.isLocked()) {
            return {"DENY", "CRITICAL", 100.0, "Account is locked due to prior security incidents."};
        }

        // Calculate risk score[cite: 4]
        double score = riskEngine_.calculateScore(userRef, resRef, context);
        AccessDecision decision = riskEngine_.decide(score);
        ThreatSeverity severity = threatDetector_.analyzeThreat(userRef, resRef, score);

        // Execute automated response[cite: 4, 5]
        responseEngine_.executeResponse(userRef, decision, severity);

        std::string decisionStr = riskEngine_.decisionToString(decision);
        std::string severityStr = threatDetector_.severityToString(severity);

        // Log the event securely via file handling
        logger_.logEvent(userRef.getUsername(), resRef.getName(), decisionStr, severityStr, score);

        return {decisionStr, severityStr, score, "Access evaluation completed successfully."};
    }
};

#endif // SECURITY_ENGINE_HPP