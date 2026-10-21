#pragma once
#include "SecurityLogger.h"
#include <string>
class DataValidationRecovery {
    SecurityLogger& logger;
    void validateFiles() const;
    void createBackups(const std::string& username,const std::string& role);
    void restoreMissing(const std::string& username,const std::string& role);
public:
    explicit DataValidationRecovery(SecurityLogger& securityLogger);
    void runMenu(const std::string& username,const std::string& role);
};
