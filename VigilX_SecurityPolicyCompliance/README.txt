VIGILX - SECURITY POLICY & COMPLIANCE EDITION

This edition extends the previous VigilX C++17 OOP security simulation with a Security Policy and Compliance Audit Engine.

NEW MODULE
- Main menu option 23: Admin: Security Policy & Compliance
- View five built-in security policies.
- Run a local audit against security logs and incident records.
- View PASS, FAIL, REVIEW REQUIRED, and DISABLED findings.
- Receive a recommendation for each finding.
- Enable or disable individual policies; settings persist in policies.txt.
- Export audit history to compliance_audit.txt and compliance_audit.csv.

BUILT-IN POLICIES
1. Repeated Failed Logins: flags a username with at least 3 failed login events.
2. Repeated Access Denials: flags a username with at least 3 denied resource access events.
3. High-Risk Access Assessment: requires review when a HIGH risk assessment appears in the logs.
4. Privileged Action Denials: requires review when role/permission administration is denied.
5. Incident Follow-up: flags incidents still marked OPEN.

BUILD (Windows PowerShell, from this folder)
g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp PasswordUtils.cpp PermissionManager.cpp SecurityPolicyEngine.cpp User.cpp Resource.cpp SecurityLogger.cpp UserManager.cpp RiskScoringEngine.cpp ResourceManager.cpp Threat.cpp ThreatSimulator.cpp IncidentResponseEngine.cpp SecurityReportGenerator.cpp SecurityDashboard.cpp VigilX.cpp -o VigilX.exe

RUN
.\VigilX.exe

FILES
- policies.txt: enabled/disabled policy configuration (created automatically).
- compliance_audit.txt: readable audit history.
- compliance_audit.csv: spreadsheet-compatible audit history.
- Existing user/resource/log/incident/permission files continue to be used as in previous versions.

IMPORTANT
This is an educational local simulation, not a certified compliance product. It evaluates the events and records available in the local text files. It does not inspect external systems, enforce external security controls, or guarantee compliance with any law or standard. Password storage and other security components are for learning purposes and should not be used as a production authentication system.

All previous VigilX features remain included. Keep previous edition folders as backups; do not nest this folder inside an older project folder.
