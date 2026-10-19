VigilX Multi-file C++17 project

BUILD (run from this folder):
g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp User.cpp Resource.cpp SecurityLogger.cpp UserManager.cpp RiskScoringEngine.cpp ResourceManager.cpp VigilX.cpp -o VigilX

RUN on Windows PowerShell:
.\VigilX.exe

RUN on Linux/macOS:
./VigilX

IMPORTANT DATA NOTE:
Copy your existing users.txt, resources.txt, and security_logs.txt into this folder before running if you want to preserve existing project data. Do not overwrite your original project until you have tested this version.

Files are split by responsibility:
- User.h/.cpp: abstract User class and Admin/Employee/Guest
- Resource.h/.cpp: Resource model
- SecurityLogger.h/.cpp: persistent logs, statistics, threat alerts
- UserManager.h/.cpp: user CRUD and users.txt persistence
- ResourceManager.h/.cpp: resource CRUD, access control, resources.txt persistence
- RiskScoringEngine.h/.cpp: risk score and risk level
- VigilX.h/.cpp: application menu, login and session
- Utils.h/.cpp: shared text/file parsing helpers
- main.cpp: program entry point
