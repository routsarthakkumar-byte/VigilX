VIGILX — Advanced Security Metrics

This edition builds on the previously tested Security Case Management project and adds main-menu option 30: Advanced Security Metrics and time-window comparisons.

QUICK START (Windows PowerShell / MinGW)
1. Extract the ZIP. Open the single top-level project folder in VS Code.
2. Open Terminal in that folder.
3. Compile:

g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp PasswordUtils.cpp PermissionManager.cpp SecurityPolicyEngine.cpp EventCorrelationEngine.cpp UserBehaviorAnalytics.cpp SecurityCaseManager.cpp ResponsePlaybookEngine.cpp AuditIntegrityEngine.cpp AlertManagementEngine.cpp AdvancedSecurityMetrics.cpp User.cpp Resource.cpp SecurityLogger.cpp UserManager.cpp RiskScoringEngine.cpp ResourceManager.cpp Threat.cpp ThreatSimulator.cpp IncidentResponseEngine.cpp SecurityReportGenerator.cpp SecurityDashboard.cpp VigilX.cpp -o VigilX.exe

4. Run: .\VigilX.exe
5. Log in as an Admin for administration features. Security analyst modules require Admin or SecurityAnalyst where stated.

DATA SAFETY
- Keep previous edition folders as backups; do not extract one edition inside another.
- Runtime data files are intentionally not bundled. To preserve data, copy relevant .txt files from your latest working edition into this folder before first run.
- All security actions are local educational simulations. No external systems are monitored or blocked.

MODULES IN THIS EDITION
- User/resource management, password authentication, permissions and roles
- Threat simulation, incident response, security reports and dashboard
- Security policy compliance, event correlation, user behavior analytics and case management
- Option 27: Automated Response Playbooks (Simulated)
- Option 28: Audit Trail & Integrity Verification
- Option 29: Alert Management & Prioritization
- Option 30: Advanced Security Metrics

This project is an educational prototype, not production-grade security software.
