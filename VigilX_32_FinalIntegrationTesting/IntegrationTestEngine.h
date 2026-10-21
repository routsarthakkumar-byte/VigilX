#pragma once
#include "SecurityLogger.h"
#include <string>
class IntegrationTestEngine {
    SecurityLogger& logger;
public:
    explicit IntegrationTestEngine(SecurityLogger& securityLogger);
    void runMenu(const std::string& username,const std::string& role);
};
