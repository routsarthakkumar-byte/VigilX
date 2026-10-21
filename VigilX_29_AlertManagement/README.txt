VIGILX — MODULE 29: Alert Management & Prioritization

This is a standalone cumulative C++17 edition. It includes the earlier VigilX features and exposes each completed module through the main menu up to option 29.

QUICK START (Windows PowerShell / MinGW)
1. Extract this ZIP. Keep its single top-level folder intact.
2. Open that folder in VS Code.
3. Open the VS Code terminal in this folder and compile:

g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp PasswordUtils.cpp PermissionManager.cpp SecurityPolicyEngine.cpp EventCorrelationEngine.cpp UserBehaviorAnalytics.cpp SecurityCaseManager.cpp ResponsePlaybookEngine.cpp AuditIntegrityEngine.cpp AlertManagementEngine.cpp User.cpp Resource.cpp SecurityLogger.cpp UserManager.cpp RiskScoringEngine.cpp ResourceManager.cpp Threat.cpp ThreatSimulator.cpp IncidentResponseEngine.cpp SecurityReportGenerator.cpp SecurityDashboard.cpp VigilX.cpp -o VigilX.exe

4. Run: .\VigilX.exe
5. Log in to use the authenticated security modules. Admin or SecurityAnalyst role is required for the administrative analysis modules.

MODULES INCLUDED
- Existing user/resource management, password authentication, roles/permissions, threat simulation, incident response, reports, dashboard and policy compliance.
- - 27. Automated Response Playbooks (Simulated)
- 28. Audit Trail & Integrity Verification
- 29. Alert Management & Prioritization

SAFETY / DATA NOTES
- This is an educational local simulation, not production security software. It does not monitor or block external systems.
- Runtime data files are not included. To preserve your data, copy the relevant .txt files from your latest working edition into this folder before first run.
- Do not extract one edition inside another or overwrite earlier folders.
