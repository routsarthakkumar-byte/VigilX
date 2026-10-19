#include "SecurityReportGenerator.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <limits>
#include <map>
#include <vector>
using namespace std;

SecurityReportGenerator::SecurityReportGenerator(SecurityLogger& securityLogger) : logger(securityLogger) {}

int SecurityReportGenerator::countLines(const string& filename) const {
    ifstream file(filename);
    string line;
    int count = 0;
    while (getline(file, line)) if (!trim(line).empty()) ++count;
    return count;
}

vector<vector<string>> SecurityReportGenerator::readIncidents() const {
    vector<vector<string>> incidents;
    ifstream file(incidentFile);
    string line;
    while (getline(file, line)) {
        vector<string> fields = splitLine(line);
        if (fields.size() >= 8) incidents.push_back(fields);
    }
    return incidents;
}

map<string, int> SecurityReportGenerator::buildMetrics() const {
    map<string, int> metrics;
    const auto logs = logger.readLogs();
    const auto incidents = readIncidents();
    metrics["Registered users"] = countLines("users.txt");
    metrics["Registered resources"] = countLines("resources.txt");
    metrics["Total security events"] = static_cast<int>(logs.size());
    metrics["Total incidents"] = static_cast<int>(incidents.size());

    for (const auto& fields : logs) {
        const string& action = fields[4];
        const string& result = fields[5];
        if (action == "LOGIN") {
            ++metrics["Login attempts"];
            if (result == "SUCCESS") ++metrics["Successful logins"];
            else if (result.find("FAILED") == 0) ++metrics["Failed logins"];
        }
        if (action.find("RESOURCE_ACCESS") == 0) {
            ++metrics["Resource access requests"];
            if (result == "GRANTED") ++metrics["Access granted"];
            else if (result.find("DENIED") == 0) ++metrics["Access denied"];
        }
        if (action.find("THREAT_SIMULATION:") == 0) ++metrics["Threat simulation events"];
        if (action.find("RISK_ASSESSMENT") == 0) {
            ++metrics["Risk assessments"];
            if (result.find("_HIGH") != string::npos) ++metrics["High-risk assessments"];
        }
    }

    for (const auto& fields : incidents) {
        const string& severity = fields[4];
        const string& status = fields[6];
        ++metrics["Severity: " + severity];
        ++metrics["Status: " + status];
    }
    return metrics;
}

void SecurityReportGenerator::runMenu() {
    int choice = -1;
    do {
        cout << "\n========== VIGILX SECURITY REPORTS =========="
             << "\n1. View Security Report"
             << "\n2. Export Report to TXT"
             << "\n3. Export Report to CSV"
             << "\n0. Return to Main Menu"
             << "\n=============================================\nChoose option: ";
        if (!(cin >> choice)) {
            cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input.\n";
            continue;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        if (choice == 1) {
            const auto metrics = buildMetrics();
            cout << "\n========== VIGILX SECURITY REPORT ==========\n";
            for (const auto& entry : metrics)
                cout << left << setw(32) << entry.first << ": " << entry.second << '\n';
            cout << "============================================\n";
            cout << "Note: Counts are based on the local text files currently available.\n";
        } else if (choice == 2) {
            if (exportTextReport()) cout << "Report exported to security_report.txt\n";
            else cout << "Could not export TXT report. Check folder permissions.\n";
        } else if (choice == 3) {
            if (exportCSVReport()) cout << "Report exported to security_report.csv\n";
            else cout << "Could not export CSV report. Check folder permissions.\n";
        } else if (choice == 0) {
            cout << "Returning to main menu.\n";
        } else {
            cout << "Invalid choice.\n";
        }
    } while (choice != 0);
}

bool SecurityReportGenerator::exportTextReport() const {
    ofstream file("security_report.txt", ios::trunc);
    if (!file.is_open()) return false;
    const auto metrics = buildMetrics();
    file << "VIGILX SECURITY REPORT\n";
    file << "======================\n";
    file << "Report source: local VigilX text data files\n\n";
    for (const auto& entry : metrics) file << entry.first << ": " << entry.second << '\n';
    file << "\nNote: This report summarizes recorded educational simulations and events.\n";
    file << "It does not certify real-world security or perform real containment.\n";
    return file.good();
}

bool SecurityReportGenerator::exportCSVReport() const {
    ofstream file("security_report.csv", ios::trunc);
    if (!file.is_open()) return false;
    const auto metrics = buildMetrics();
    file << "Metric,Value\n";
    for (const auto& entry : metrics) file << '"' << entry.first << "\"," << entry.second << '\n';
    return file.good();
}
