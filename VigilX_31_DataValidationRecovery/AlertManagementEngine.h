#pragma once
#include "SecurityLogger.h"
#include <string>
class AlertManagementEngine {
    SecurityLogger& logger;
    void generateAlerts(const std::string& actor,const std::string& role);
    void viewAlerts() const;
    void updateAlert(const std::string& actor,const std::string& role);
    void exportAlerts() const;
public:
    explicit AlertManagementEngine(SecurityLogger& securityLogger);
    void runMenu(const std::string& username,const std::string& role);
};
