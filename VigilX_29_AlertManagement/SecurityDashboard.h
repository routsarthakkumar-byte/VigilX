#pragma once
#include "SecurityLogger.h"
#include <string>
#include <vector>

class SecurityDashboard {
private:
    SecurityLogger& logger;
    int countLines(const std::string& filename) const;
    std::vector<std::vector<std::string>> readIncidents() const;
    void showOverview() const;
    void showRecentActivity() const;
    void showIncidentSummary() const;
public:
    explicit SecurityDashboard(SecurityLogger& securityLogger);
    void runMenu() const;
};
