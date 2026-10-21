#pragma once
#include "SecurityLogger.h"
#include <string>
#include <vector>

struct BehaviorProfile {
    std::string username;
    int successfulLogins = 0;
    int failedLogins = 0;
    int grantedAccess = 0;
    int deniedAccess = 0;
    int highRiskAssessments = 0;
    int failedPasswordChanges = 0;
    int riskScore = 0;
    std::string riskLevel;
    std::vector<std::string> evidenceIDs;
    std::vector<std::string> reasons;
};

class UserBehaviorAnalytics {
private:
    SecurityLogger& logger;
    const std::string textReport = "user_behavior_report.txt";
    const std::string csvReport = "user_behavior_report.csv";
    std::vector<BehaviorProfile> analyze() const;
    void exportReports(const std::vector<BehaviorProfile>& profiles) const;
    void viewSavedReport() const;
public:
    explicit UserBehaviorAnalytics(SecurityLogger& securityLogger);
    void runMenu(const std::string& username, const std::string& role);
};
