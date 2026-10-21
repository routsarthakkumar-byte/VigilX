#pragma once
#include "SecurityLogger.h"
#include <string>
class ResponsePlaybookEngine {
    SecurityLogger& logger;
    void showPlaybooks() const;
    void evaluateAndSimulate(const std::string& actor, const std::string& role);
    void exportReport() const;
public:
    explicit ResponsePlaybookEngine(SecurityLogger& securityLogger);
    void runMenu(const std::string& username, const std::string& role);
};
