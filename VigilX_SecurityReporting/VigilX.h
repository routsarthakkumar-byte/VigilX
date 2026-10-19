#pragma once
#include "SecurityLogger.h"
#include "UserManager.h"
#include "ResourceManager.h"
#include "ThreatSimulator.h"
#include "IncidentResponseEngine.h"
#include "SecurityReportGenerator.h"
class VigilX {
private:
    SecurityLogger logger; UserManager userManager; ResourceManager resourceManager; ThreatSimulator threatSimulator; IncidentResponseEngine incidentResponse; SecurityReportGenerator reportGenerator; int currentUserID=-1;
    User* getCurrentUser() const; void login(); void logout(); void viewSession() const; void accessControl();
public: VigilX(); void run();
};
