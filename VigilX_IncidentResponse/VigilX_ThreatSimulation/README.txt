VigilX - Threat Simulation and Incident Response Engine (C++17)

BUILD COMMAND (run inside this folder in VS Code terminal):
g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp User.cpp Resource.cpp SecurityLogger.cpp UserManager.cpp RiskScoringEngine.cpp ResourceManager.cpp Threat.cpp ThreatSimulator.cpp IncidentResponseEngine.cpp VigilX.cpp -o VigilX.exe

RUN (Windows PowerShell):
.\VigilX.exe

DATA PRESERVATION:
If you want your previous data, copy users.txt, resources.txt and security_logs.txt from your previous working project into this folder before running. Keep the older folder as a backup. incidents.txt is created automatically when the Incident Response module first creates an incident.

MAIN MENU:
Option 15: Threat Simulator
Option 16: Incident Response

THREAT SIMULATOR:
Includes Brute Force Attack, Unauthorized Access, Suspicious Login, Privilege Escalation, Abnormal Resource Access, and Custom Scenario. These are controlled simulations only. No real network traffic, real login attempts, actual resource access, or permission changes are performed.

INCIDENT RESPONSE (NEW):
1. Detect threats from security logs and create incident records.
2. View the incident register.
3. Update incident status to INVESTIGATING, CONTAINED_SIMULATED, or RESOLVED.
4. Each incident records a severity, username, source event ID, status, and response action. Duplicate detections for the same source event are avoided.
5. Simulated containment only records an educational response; it does not block accounts or alter real systems.

Existing features retained: user/resource CRUD, persistence, login by ID and username, RBAC, risk scoring, security logs, statistics, threat alerts, and threat simulation.

Educational prototype only: login is not password-based, and plain-text files are not secure production storage.
