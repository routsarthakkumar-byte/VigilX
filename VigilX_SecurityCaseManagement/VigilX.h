#pragma once
#include "SecurityLogger.h"
#include "UserManager.h"
#include "ResourceManager.h"
#include "ThreatSimulator.h"
#include "IncidentResponseEngine.h"
#include "SecurityReportGenerator.h"
#include "SecurityDashboard.h"
#include "PermissionManager.h"
#include "SecurityPolicyEngine.h"
#include "EventCorrelationEngine.h"
#include "UserBehaviorAnalytics.h"
#include "SecurityCaseManager.h"
class VigilX {
private:
    SecurityLogger logger; UserManager userManager; ResourceManager resourceManager; ThreatSimulator threatSimulator; IncidentResponseEngine incidentResponse; SecurityReportGenerator reportGenerator; SecurityDashboard dashboard; PermissionManager permissionManager; SecurityPolicyEngine policyEngine; EventCorrelationEngine correlationEngine; UserBehaviorAnalytics behaviorAnalytics; SecurityCaseManager caseManager; int currentUserID=-1;
    User* getCurrentUser() const; void login(); void logout(); void viewSession() const; void accessControl(); void changeOwnPassword(); void unlockAccount(); void manageRoles(); void managePermissions(); void managePolicies(); void runEventCorrelation(); void runBehaviorAnalytics(); void runCaseManagement();
public: VigilX(); void run();
};
