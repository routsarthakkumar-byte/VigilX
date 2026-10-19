VigilX - Threat Simulation Engine (C++17)

Build from this folder in VS Code terminal:
g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp User.cpp Resource.cpp SecurityLogger.cpp UserManager.cpp RiskScoringEngine.cpp ResourceManager.cpp Threat.cpp ThreatSimulator.cpp VigilX.cpp -o VigilX.exe

Run in Windows PowerShell:
.\VigilX.exe

Before first run, copy your existing users.txt, resources.txt and security_logs.txt from the previous working folder into this folder if you want to preserve existing data. Do not delete your old project.

New feature: choose option 15 (Threat Simulator). It includes Brute Force Attack, Unauthorized Access, Suspicious Login, Privilege Escalation, Abnormal Resource Access, and Custom Scenario. These are controlled simulations: no network traffic, real login attempts, real resource access, or real permission changes occur. Events are appended to security_logs.txt. The brute-force simulation generates repeated failed-login records, and abnormal-access simulation generates denied-access records, so existing alert rules can demonstrate detection.

Existing features are retained: user/resource CRUD, persistence, login by ID and username, RBAC, risk scoring, logs, statistics, and threat alerts. Educational prototype; current login is not password-based and text files are not secure production storage.
