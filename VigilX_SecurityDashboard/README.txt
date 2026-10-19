VIGILX - SECURITY DASHBOARD EDITION
===================================

This version includes the previous C++ OOP modules plus a Security Dashboard.

Main menu option 18: Security Dashboard
  1. View Overall Security Overview
  2. View Recent Security Activity (latest 5 events)
  3. View Incident Summary
  0. Return to Main Menu

Build with MinGW g++ (C++17):
g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp User.cpp Resource.cpp SecurityLogger.cpp UserManager.cpp RiskScoringEngine.cpp ResourceManager.cpp Threat.cpp ThreatSimulator.cpp IncidentResponseEngine.cpp SecurityReportGenerator.cpp SecurityDashboard.cpp VigilX.cpp -o VigilX.exe

Run in PowerShell:
.\VigilX.exe

Data files such as users.txt, resources.txt, security_logs.txt, and incidents.txt are created as the application uses those modules. To preserve data from an earlier version, copy the files into this folder before running. Do not overwrite the older project folder.

The dashboard reads local educational-project data files only. It does not monitor real external systems or perform real containment/blocking.
