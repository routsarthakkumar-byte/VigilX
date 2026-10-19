#pragma once
#include "SecurityLogger.h"
#include "UserManager.h"
#include "ResourceManager.h"
#include "ThreatSimulator.h"
class VigilX {
private:
    SecurityLogger logger; UserManager userManager; ResourceManager resourceManager; ThreatSimulator threatSimulator; int currentUserID=-1;
    User* getCurrentUser() const; void login(); void logout(); void viewSession() const; void accessControl();
public: VigilX(); void run();
};
