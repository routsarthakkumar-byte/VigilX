#ifndef RESPONSE_ENGINE_HPP
#define RESPONSE_ENGINE_HPP

#include "User.hpp"
#include "RiskEngine.hpp"
#include "ThreatDetector.hpp"
#include <string>
#include <iostream>

class ResponseEngine {
public:
    void executeResponse(User& user, AccessDecision decision, ThreatSeverity severity) const {
        switch (decision) {
            case AccessDecision::DENY:
                user.setLocked(true); // Automatically lock the account on high-risk breaches[cite: 4, 5]
                std::cout << "[RESPONSE ENGINE] CRITICAL: Access DENIED and Account LOCKED for user: " 
                          << user.getUsername() << " due to severe threat level.\n";
                break;

            case AccessDecision::RESTRICT:
                std::cout << "[RESPONSE ENGINE] WARNING: Access RESTRICTED to read-only for user: " 
                          << user.getUsername() << ".\n";
                break;

            case AccessDecision::ALLOW_MONITOR:
                std::cout << "[RESPONSE ENGINE] NOTICE: Access granted with active monitoring for user: " 
                          << user.getUsername() << ".\n";
                break;

            case AccessDecision::ALLOW:
                // Normal access, no special mitigation required[cite: 4]
                break;
        }
    }
};

#endif // RESPONSE_ENGINE_HPP