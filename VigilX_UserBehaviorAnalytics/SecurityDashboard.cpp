#include "SecurityDashboard.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <map>
#include <algorithm>
#include <limits>
using namespace std;

SecurityDashboard::SecurityDashboard(SecurityLogger& securityLogger) : logger(securityLogger) {}

int SecurityDashboard::countLines(const string& filename) const {
    ifstream file(filename);
    string line;
    int count = 0;
    while (getline(file, line)) if (!trim(line).empty()) ++count;
    return count;
}

vector<vector<string>> SecurityDashboard::readIncidents() const {
    vector<vector<string>> incidents;
    ifstream file("incidents.txt");
    string line;
    while (getline(file, line)) {
        auto fields = splitLine(line);
        if (fields.size() >= 8) incidents.push_back(fields);
    }
    return incidents;
}

void SecurityDashboard::showOverview() const {
    const auto logs = logger.readLogs();
    const auto incidents = readIncidents();
    int failedLogins = 0, deniedAccess = 0, threatEvents = 0, highRisk = 0;
    int successfulLogins = 0, grantedAccess = 0;
    map<string, int> usersWithFailedLogins;
    map<string, int> severityCounts;
    map<string, int> statusCounts;

    for (const auto& row : logs) {
        if (row.size() < 6) continue;
        const string& username = row[2];
        const string& action = row[4];
        const string& result = row[5];
        if (action == "LOGIN" && result == "SUCCESS") ++successfulLogins;
        if (action == "LOGIN" && result.find("FAILED") == 0) {
            ++failedLogins;
            ++usersWithFailedLogins[username];
        }
        if (action.find("RESOURCE_ACCESS") == 0 && result == "GRANTED") ++grantedAccess;
        if (action.find("RESOURCE_ACCESS") == 0 && result.find("DENIED") == 0) ++deniedAccess;
        if (action.find("THREAT_SIMULATION:") == 0) ++threatEvents;
        if (action.find("RISK_ASSESSMENT") == 0 && result.find("_HIGH") != string::npos) ++highRisk;
    }
    for (const auto& incident : incidents) {
        ++severityCounts[incident[4]];
        ++statusCounts[incident[6]];
    }

    int repeatedFailedLoginUsers = 0;
    for (const auto& entry : usersWithFailedLogins) if (entry.second >= 3) ++repeatedFailedLoginUsers;

    cout << "\n================ VIGILX SECURITY DASHBOARD ================\n";
    cout << left << setw(34) << "Registered users" << ": " << countLines("users.txt") << '\n';
    cout << left << setw(34) << "Registered resources" << ": " << countLines("resources.txt") << '\n';
    cout << left << setw(34) << "Total security events" << ": " << logs.size() << '\n';
    cout << left << setw(34) << "Successful logins" << ": " << successfulLogins << '\n';
    cout << left << setw(34) << "Failed logins" << ": " << failedLogins << '\n';
    cout << left << setw(34) << "Repeated-failure usernames (3+)" << ": " << repeatedFailedLoginUsers << '\n';
    cout << left << setw(34) << "Access granted" << ": " << grantedAccess << '\n';
    cout << left << setw(34) << "Access denied" << ": " << deniedAccess << '\n';
    cout << left << setw(34) << "Threat simulation events" << ": " << threatEvents << '\n';
    cout << left << setw(34) << "High-risk assessments" << ": " << highRisk << '\n';
    cout << left << setw(34) << "Total recorded incidents" << ": " << incidents.size() << '\n';
    cout << "\nIncident severity summary\n";
    const vector<string> severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"};
    for (const auto& severity : severities)
        cout << "  " << left << setw(12) << severity << ": " << severityCounts[severity] << '\n';
    cout << "\nIncident status summary\n";
    if (statusCounts.empty()) cout << "  No incidents recorded yet.\n";
    else for (const auto& entry : statusCounts) cout << "  " << left << setw(24) << entry.first << ": " << entry.second << '\n';
    cout << "\nNote: Values are calculated from the local VigilX data files.\n";
    cout << "This educational dashboard does not monitor external systems.\n";
    cout << "===========================================================\n";
}

void SecurityDashboard::showRecentActivity() const {
    const auto logs = logger.readLogs();
    cout << "\n================ VIGILX RECENT ACTIVITY ==================\n";
    if (logs.empty()) {
        cout << "No security events found.\n";
        return;
    }
    size_t start = logs.size() > 5 ? logs.size() - 5 : 0;
    for (size_t i = start; i < logs.size(); ++i) {
        const auto& row = logs[i];
        if (row.size() < 6) continue;
        cout << "Event #" << row[0] << " | " << row[1] << '\n'
             << "User: " << row[2] << " (" << row[3] << ")\n"
             << "Action: " << row[4] << " | Result: " << row[5] << '\n'
             << "-----------------------------------------------------------\n";
    }
    cout << "Showing up to the latest 5 recorded events.\n";
}

void SecurityDashboard::showIncidentSummary() const {
    const auto incidents = readIncidents();
    cout << "\n================ VIGILX INCIDENT SUMMARY ==================\n";
    if (incidents.empty()) {
        cout << "No incidents recorded yet. Use option 16 to detect threats.\n";
        return;
    }
    for (const auto& item : incidents) {
        cout << "Incident #" << item[0] << " | " << item[4] << " | " << item[6] << '\n'
             << "Type: " << item[3] << " | User: " << item[2] << '\n'
             << "Response: " << item[7] << '\n'
             << "-----------------------------------------------------------\n";
    }
    cout << "Total incidents: " << incidents.size() << '\n';
}

void SecurityDashboard::runMenu() const {
    int choice = -1;
    do {
        cout << "\n========== VIGILX SECURITY DASHBOARD ==========\n"
             << "1. View Overall Security Overview\n"
             << "2. View Recent Security Activity\n"
             << "3. View Incident Summary\n"
             << "0. Return to Main Menu\n"
             << "===============================================\nChoose option: ";
        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input. Please enter a number.\n";
            continue;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        switch (choice) {
            case 1: showOverview(); break;
            case 2: showRecentActivity(); break;
            case 3: showIncidentSummary(); break;
            case 0: cout << "Returning to main menu.\n"; break;
            default: cout << "Invalid choice.\n"; break;
        }
    } while (choice != 0);
}
