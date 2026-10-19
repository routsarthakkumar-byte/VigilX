#ifndef RISK_ENGINE_HPP
#define RISK_ENGINE_HPP

#include "RiskFactor.hpp"
#include <vector>
#include <memory>
#include <numeric>
#include <string>
#include <algorithm> // For std::min and std::max

enum class AccessDecision {
    ALLOW,             // 0-30: Grant access normally[cite: 4]
    ALLOW_MONITOR,     // 31-60: Grant access and log the event[cite: 4]
    RESTRICT,          // 61-80: Read-only access and raise an alert[cite: 4]
    DENY               // 81-100: Block, lock the account, log an incident[cite: 4]
};

class RiskEngine {
private:
    std::vector<std::unique_ptr<RiskFactor>> factors_;
    std::vector<double> weights_;

public:
    RiskEngine() {
        // Register factors and their corresponding weights as specified in VigilX architecture
        factors_.push_back(std::make_unique<RoleMismatchFactor>());
        weights_.push_back(30.0); // Role Mismatch weight[cite: 4]

        factors_.push_back(std::make_unique<FailedLoginFactor>());
        weights_.push_back(25.0); // Failed Login weight[cite: 4]

        factors_.push_back(std::make_unique<ResourceSensitivityFactor>());
        weights_.push_back(25.0); // Resource Sensitivity weight[cite: 4]

        factors_.push_back(std::make_unique<TimeAnomalyFactor>());
        weights_.push_back(10.0); // Time Anomaly weight[cite: 4]

        factors_.push_back(std::make_unique<AccessFrequencyFactor>());
        weights_.push_back(10.0); // Access Frequency weight[cite: 4]
    }

    double calculateScore(const User& user, const Resource& resource, const AccessContext& context) const {
        double totalRisk = 0.0;
        double totalWeight = 0.0;

        for (size_t i = 0; i < factors_.size(); ++i) {
            double factorVal = factors_[i]->evaluate(user, resource, context);
            totalRisk += factorVal * weights_[i];
            totalWeight += weights_[i];
        }

        // Normalize and bound to 0-100 scale using min/max for compatibility[cite: 4]
        if (totalWeight > 0) {
            totalRisk = (totalRisk / totalWeight) * 100.0;
        }

        return std::max(0.0, std::min(100.0, totalRisk));
    }

    AccessDecision decide(double score) const {
        if (score <= 30.0) {
            return AccessDecision::ALLOW;         // 0-30[cite: 4]
        } else if (score <= 60.0) {
            return AccessDecision::ALLOW_MONITOR; // 31-60[cite: 4]
        } else if (score <= 80.0) {
            return AccessDecision::RESTRICT;      // 61-80[cite: 4]
        } else {
            return AccessDecision::DENY;          // 81-100[cite: 4]
        }
    }

    std::string decisionToString(AccessDecision decision) const {
        switch (decision) {
            case AccessDecision::ALLOW: return "ALLOW";
            case AccessDecision::ALLOW_MONITOR: return "ALLOW + MONITOR";
            case AccessDecision::RESTRICT: return "RESTRICT";
            case AccessDecision::DENY: return "DENY";
        }
        return "UNKNOWN";
    }
};

#endif // RISK_ENGINE_HPP