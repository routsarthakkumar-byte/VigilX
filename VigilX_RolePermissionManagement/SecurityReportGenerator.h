#pragma once
#include "SecurityLogger.h"
#include <string>
#include <vector>
#include <map>

class SecurityReportGenerator {
private:
    SecurityLogger& logger;
    std::string incidentFile = "incidents.txt";
    int countLines(const std::string& filename) const;
    std::vector<std::vector<std::string>> readIncidents() const;
    std::map<std::string, int> buildMetrics() const;
    bool exportTextReport() const;
    bool exportCSVReport() const;
public:
    explicit SecurityReportGenerator(SecurityLogger& securityLogger);
    void runMenu();
};
