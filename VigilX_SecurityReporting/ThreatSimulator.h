#pragma once
#include "SecurityLogger.h"
class ThreatSimulator {
private: SecurityLogger& logger;
public: explicit ThreatSimulator(SecurityLogger& securityLogger); void runMenu();
};
