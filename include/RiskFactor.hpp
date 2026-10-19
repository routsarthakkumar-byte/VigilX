#ifndef RISK_FACTOR_HPP
#define RISK_FACTOR_HPP

#include "User.hpp"
#include "Resource.hpp"
#include <memory>
#include <algorithm>

struct AccessContext {
    int currentHour;
    int requestFrequency;
    bool isUnusualPattern;
};

class RiskFactor {
public:
    virtual ~RiskFactor() = default;
    virtual double evaluate(const User& user, const Resource& resource, const AccessContext& context) const = 0;
};

// 1. Role Mismatch Factor (Weight: 30)
class RoleMismatchFactor : public RiskFactor {
public:
    double evaluate(const User& user, const Resource& resource, const AccessContext&) const override {
        if (static_cast<int>(user.getRole()) < static_cast<int>(resource.getMinimumRequiredRole())) {
            return 1.0; // Maximum risk penalty for role mismatch
        }
        return 0.0;
    }
};

// 2. Failed Login Factor (Weight: 25)
class FailedLoginFactor : public RiskFactor {
public:
    double evaluate(const User& user, const Resource&, const AccessContext&) const override {
        int attempts = user.getFailedAttempts();
        if (attempts <= 0) return 0.0;
        return std::min(1.0, static_cast<double>(attempts) / 5.0);
    }
};

// 3. Resource Sensitivity Factor (Weight: 25)
class ResourceSensitivityFactor : public RiskFactor {
public:
    double evaluate(const User&, const Resource& resource, const AccessContext&) const override {
        switch (resource.getSensitivity()) {
            case SensitivityLevel::LOW: return 0.25;
            case SensitivityLevel::MEDIUM: return 0.50;
            case SensitivityLevel::HIGH: return 0.75;
            case SensitivityLevel::CRITICAL: return 1.00;
        }
        return 0.5;
    }
};

// 4. Time Anomaly Factor (Weight: 10)
class TimeAnomalyFactor : public RiskFactor {
public:
    double evaluate(const User&, const Resource&, const AccessContext& context) const override {
        // Flag unusual hours (e.g., between midnight and 5 AM)
        if (context.currentHour >= 0 && context.currentHour <= 5) {
            return 1.0;
        }
        return 0.0;
    }
};

// 5. Access Frequency Factor (Weight: 10)
class AccessFrequencyFactor : public RiskFactor {
public:
    double evaluate(const User&, const Resource&, const AccessContext& context) const override {
        if (context.requestFrequency > 20) return 1.0; // High velocity request rate
        return static_cast<double>(context.requestFrequency) / 20.0;
    }
};

#endif // RISK_FACTOR_HPP