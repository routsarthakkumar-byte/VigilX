#ifndef THREAT_DETECTOR_HPP
#define THREAT_DETECTOR_HPP

#include <string>
#include "User.hpp"
#include "Resource.hpp"

enum class ThreatSeverity { LOW, MEDIUM, HIGH, CRITICAL };

class ThreatDetector {
public:
    ThreatSeverity analyzeThreat(const User& user, const Resource& resource, double riskScore) const {
        if (user.isLocked() || riskScore >= 85.0) {
            return ThreatSeverity::CRITICAL;
        } else if (riskScore >= 65.0) {
            return ThreatSeverity::HIGH;
        } else if (riskScore >= 35.0) {
            return ThreatSeverity::MEDIUM;
        }
        return ThreatSeverity::LOW;
    }

    std::string severityToString(ThreatSeverity severity) const {
        switch (severity) {
            case ThreatSeverity::LOW: return "LOW";
            case ThreatSeverity::MEDIUM: return "MEDIUM";
            case ThreatSeverity::HIGH: return "HIGH";
            case ThreatSeverity::CRITICAL: return "CRITICAL";
        }
        return "UNKNOWN";
    }
};

#endif // THREAT_DETECTOR_HPP