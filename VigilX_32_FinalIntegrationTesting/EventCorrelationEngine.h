#pragma once
#include "SecurityLogger.h"
#include <string>
#include <vector>

struct CorrelationFinding {
    std::string username;
    std::string severity;
    std::string pattern;
    std::string evidence;
    std::string recommendation;
};

class EventCorrelationEngine {
private:
    SecurityLogger& logger;
    const std::string textReport = "event_correlation.txt";
    const std::string csvReport = "event_correlation.csv";
    std::vector<CorrelationFinding> correlate() const;
    void exportReports(const std::vector<CorrelationFinding>& findings) const;
    void viewSavedReport() const;
public:
    explicit EventCorrelationEngine(SecurityLogger& securityLogger);
    void runMenu(const std::string& username, const std::string& role);
};
