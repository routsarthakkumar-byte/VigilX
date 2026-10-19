VIGILX - EVENT CORRELATION & ATTACK CHAIN ANALYSIS EDITION

This edition extends the previous VigilX C++17 OOP security simulation with a local event-correlation module.

NEW MODULE
- Main menu option 24: Event Correlation & Attack Chain Analysis.
- Accessible to a logged-in Admin (or SecurityAnalyst if that role is enabled in the project).
- Correlates events by username across the readable security_logs.txt history.
- Detects repeated failed logins, failed logins combined with access denials, high-risk assessments combined with simulated threat activity, and repeated access denials.
- Shows severity, evidence event IDs, and suggested review actions.
- Exports event_correlation.txt and event_correlation.csv.
- Lets authorized users view the most recently saved report.

CORRELATION RULES
1. At least 3 failed login events for a username -> HIGH.
2. At least one failed login and one denied resource access event for a username -> HIGH.
3. At least one high-risk assessment and one simulated threat event for a username -> CRITICAL.
4. At least 3 denied resource access events for a username -> MEDIUM.

BUILD (Windows PowerShell, from this folder)
g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp PasswordUtils.cpp PermissionManager.cpp SecurityPolicyEngine.cpp EventCorrelationEngine.cpp User.cpp Resource.cpp SecurityLogger.cpp UserManager.cpp RiskScoringEngine.cpp ResourceManager.cpp Threat.cpp ThreatSimulator.cpp IncidentResponseEngine.cpp SecurityReportGenerator.cpp SecurityDashboard.cpp VigilX.cpp -o VigilX.exe

RUN
.\VigilX.exe

FILES
- event_correlation.txt: readable latest correlation report.
- event_correlation.csv: spreadsheet-compatible latest correlation report.
- Existing user/resource/log/incident/permission/policy files are used as in the previous edition.

IMPORTANT
This is an educational local simulation. It scans events present in local security_logs.txt, groups evidence by username across the available history, and uses simple heuristic rules. It does not establish causality, prove an attack, monitor external systems, or take real containment actions. Review findings before making decisions. Keep previous edition folders as backups; do not nest this folder inside an older project folder.
