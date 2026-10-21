#pragma once
#include "SecurityLogger.h"
#include <string>
class AuditIntegrityEngine {
    SecurityLogger& logger;
    void createBaseline(const std::string& actor,const std::string& role);
    void verifyBaseline(const std::string& actor,const std::string& role);
    void showBaseline() const;
public:
    explicit AuditIntegrityEngine(SecurityLogger& securityLogger);
    void runMenu(const std::string& username,const std::string& role);
};
