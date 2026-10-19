#pragma once
#include <string>
#include <vector>
class SecurityLogger {
private: std::string filename = "security_logs.txt"; int nextEventID = 1;
public:
    SecurityLogger();
    void logEvent(const std::string& username, const std::string& role, const std::string& action, const std::string& result);
    std::vector<std::vector<std::string>> readLogs() const;
    int countPreviousDeniedRequests(const std::string& username) const;
    void viewLogs() const; void viewStatistics() const; void viewThreatAlerts() const;
};
