#pragma once
#include "SecurityLogger.h"
#include <string>
class AdvancedSecurityMetrics {
    SecurityLogger& logger;
    void showMetrics() const;
    void exportMetrics() const;
public:
    explicit AdvancedSecurityMetrics(SecurityLogger& securityLogger);
    void runMenu(const std::string& username,const std::string& role);
};
