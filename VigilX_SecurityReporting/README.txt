VigilX - Threat Simulation, Incident Response and Security Reporting Engine (C++17)

BUILD COMMAND (run inside this folder in VS Code terminal):
g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp User.cpp Resource.cpp SecurityLogger.cpp UserManager.cpp RiskScoringEngine.cpp ResourceManager.cpp Threat.cpp ThreatSimulator.cpp IncidentResponseEngine.cpp SecurityReportGenerator.cpp VigilX.cpp -o VigilX.exe

RUN (Windows PowerShell):
.\VigilX.exe

DATA PRESERVATION:
To carry forward existing records, copy users.txt, resources.txt, security_logs.txt and incidents.txt from your previous working project into this folder before running. Keep older folders as backups. Files that do not exist will be created as needed.

MAIN MENU:
Option 15: Threat Simulator
Option 16: Incident Response
Option 17: Security Reports / Analytics

SECURITY REPORTS / ANALYTICS (NEW):
1. View a consolidated summary of users, resources, security events, login activity, resource access decisions, threat simulation events, risk assessments, incident severity and incident status.
2. Export the report as security_report.txt.
3. Export the report as security_report.csv for spreadsheet analysis.
Reports are generated from the local text data files currently available. Missing data files are treated as empty.

THREAT SIMULATOR:
Includes Brute Force Attack, Unauthorized Access, Suspicious Login, Privilege Escalation, Abnormal Resource Access, and Custom Scenario. These are controlled simulations only. No real network traffic, real login attempts, actual resource access, or permission changes are performed.

INCIDENT RESPONSE:
1. Detect threats from security logs and create incident records.
2. View the incident register.
3. Update incident status to INVESTIGATING, CONTAINED_SIMULATED, or RESOLVED.
Containment is simulated only; it does not block accounts or alter real systems.

Existing features retained: user/resource CRUD, persistence, login by ID and username, RBAC, risk scoring, security logs, statistics, threat alerts, threat simulation, incident response.

Educational prototype only: login is not password-based, and plain-text files are not secure production storage.
