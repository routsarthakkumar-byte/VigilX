#pragma once
#include "SecurityLogger.h"
#include <string>
#include <vector>

struct SecurityCase {
    int id = 0;
    std::string title;
    std::string severity;
    std::string status;
    std::string owner;
    std::string username;
    std::string evidence;
    std::string notes;
};

class SecurityCaseManager {
private:
    SecurityLogger& logger;
    const std::string dataFile = "security_cases.txt";
    const std::string textReport = "security_case_report.txt";
    const std::string csvReport = "security_case_report.csv";
    std::vector<SecurityCase> loadCases() const;
    bool saveCases(const std::vector<SecurityCase>& cases) const;
    void createCase(const std::string& actor, const std::string& role);
    void viewCases() const;
    void updateStatus(const std::string& actor, const std::string& role);
    void addInvestigationNote(const std::string& actor, const std::string& role);
    void exportReport() const;
    void viewRecentEvents() const;
public:
    explicit SecurityCaseManager(SecurityLogger& securityLogger);
    void runMenu(const std::string& username, const std::string& role);
};
