#include "IncidentResponseEngine.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <map>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <limits>
#include <algorithm>
using namespace std;

IncidentResponseEngine::IncidentResponseEngine(SecurityLogger& securityLogger) : logger(securityLogger) {}

vector<Incident> IncidentResponseEngine::readIncidents() const {
    vector<Incident> incidents;
    ifstream file(filename);
    string line;
    while (getline(file, line)) {
        vector<string> f = splitLine(line);
        if (f.size() < 8) continue;
        try {
            Incident item;
            item.id = stoi(f[0]);
            item.timestamp = f[1];
            item.username = f[2];
            item.type = f[3];
            item.severity = f[4];
            item.sourceEventID = stoi(f[5]);
            item.status = f[6];
            item.responseAction = f[7];
            incidents.push_back(item);
        } catch (...) {}
    }
    return incidents;
}

bool IncidentResponseEngine::saveIncident(const Incident& incident) const {
    ofstream file(filename, ios::app);
    if (!file.is_open()) {
        cout << "Could not save incident. Check folder permissions.\n";
        return false;
    }
    file << incident.id << " | " << cleanField(incident.timestamp) << " | "
         << cleanField(incident.username) << " | " << cleanField(incident.type) << " | "
         << cleanField(incident.severity) << " | " << incident.sourceEventID << " | "
         << cleanField(incident.status) << " | " << cleanField(incident.responseAction) << '\n';
    return file.good();
}

bool IncidentResponseEngine::alreadyExists(const vector<Incident>& incidents, const string& username,
                                            const string& type, int sourceEventID) const {
    for (const Incident& item : incidents) {
        if (item.username == username && item.type == type && item.sourceEventID == sourceEventID)
            return true;
    }
    return false;
}

void IncidentResponseEngine::detectAndCreateIncidents() {
    vector<vector<string>> logs = logger.readLogs();
    vector<Incident> incidents = readIncidents();
    map<string, int> failedCount, failedLatest, deniedCount, deniedLatest;
    vector<Incident> candidates;

    for (const auto& f : logs) {
        int eventID = 0;
        try { eventID = stoi(f[0]); } catch (...) { continue; }
        const string& username = f[2];
        const string& action = f[4];
        const string& result = f[5];

        if (action == "LOGIN" && result.find("FAILED") == 0) {
            ++failedCount[username];
            failedLatest[username] = eventID;
        }
        if (action.find("RESOURCE_ACCESS") == 0 && result.find("DENIED") == 0) {
            ++deniedCount[username];
            deniedLatest[username] = eventID;
        }

        string type, severity;
        if (action.find("RISK_ASSESSMENT") == 0 && result.find("_HIGH") != string::npos) {
            type = "High-Risk Access Activity"; severity = "HIGH";
        } else if (action.find("THREAT_SIMULATION:PRIVILEGE_ESCALATION") == 0) {
            type = "Privilege Escalation Attempt"; severity = "CRITICAL";
        } else if (action.find("THREAT_SIMULATION:UNAUTHORIZED_ACCESS") == 0) {
            type = "Simulated Unauthorized Access"; severity = "HIGH";
        } else if (action.find("THREAT_SIMULATION:SUSPICIOUS_LOGIN") == 0) {
            type = "Suspicious Login"; severity = "MEDIUM";
        } else if (action.find("THREAT_SIMULATION:CUSTOM:") == 0) {
            type = "Custom Simulated Threat";
            if (result.find("CRITICAL") == 0) severity = "CRITICAL";
            else if (result.find("HIGH") == 0) severity = "HIGH";
            else if (result.find("MEDIUM") == 0) severity = "MEDIUM";
            else severity = "LOW";
        }
        if (!type.empty()) {
            Incident item;
            item.username = username; item.type = type; item.severity = severity;
            item.sourceEventID = eventID;
            candidates.push_back(item);
        }
    }

    for (const auto& entry : failedCount) {
        if (entry.second >= 3) {
            Incident item; item.username = entry.first; item.type = "Repeated Failed Logins";
            item.severity = "HIGH"; item.sourceEventID = failedLatest[entry.first];
            candidates.push_back(item);
        }
    }
    for (const auto& entry : deniedCount) {
        if (entry.second >= 3) {
            Incident item; item.username = entry.first; item.type = "Repeated Access Denials";
            item.severity = "MEDIUM"; item.sourceEventID = deniedLatest[entry.first];
            candidates.push_back(item);
        }
    }

    int largestID = 0;
    for (const Incident& item : incidents) largestID = max(largestID, item.id);
    int created = 0;
    for (Incident item : candidates) {
        if (alreadyExists(incidents, item.username, item.type, item.sourceEventID)) continue;
        time_t now = time(nullptr); tm* localTime = localtime(&now);
        stringstream timestamp;
        if (localTime) timestamp << put_time(localTime, "%Y-%m-%d %H:%M:%S");
        else timestamp << "Unknown";
        item.id = ++largestID;
        item.timestamp = timestamp.str();
        item.status = "OPEN";
        item.responseAction = "Pending review";
        if (saveIncident(item)) {
            incidents.push_back(item);
            ++created;
            logger.logEvent(item.username, "SecurityAnalyst", "INCIDENT_CREATED", item.severity + "_" + item.type);
            cout << "Created incident #" << item.id << " [" << item.severity << "] " << item.type
                 << " for " << item.username << ".\n";
        }
    }
    if (created == 0) cout << "No new incidents detected. Existing incidents were not duplicated.\n";
    else cout << "Detection complete. New incidents created: " << created << '\n';
}

void IncidentResponseEngine::viewIncidents() const {
    vector<Incident> incidents = readIncidents();
    cout << "\n================ VIGILX INCIDENT REGISTER ================\n";
    if (incidents.empty()) {
        cout << "No incidents recorded yet. Run Detect Threats first.\n";
        return;
    }
    for (const Incident& item : incidents) {
        cout << "Incident ID : " << item.id << '\n'
             << "Created     : " << item.timestamp << '\n'
             << "Username    : " << item.username << '\n'
             << "Type        : " << item.type << '\n'
             << "Severity    : " << item.severity << '\n'
             << "Source Event: #" << item.sourceEventID << '\n'
             << "Status      : " << item.status << '\n'
             << "Response    : " << item.responseAction << '\n'
             << "---------------------------------------------------------\n";
    }
    cout << "Total incidents: " << incidents.size() << '\n';
}

void IncidentResponseEngine::updateIncidentStatus() {
    vector<Incident> incidents = readIncidents();
    if (incidents.empty()) {
        cout << "No incidents available. Run Detect Threats first.\n";
        return;
    }
    int id;
    cout << "Enter incident ID to update: ";
    if (!(cin >> id)) {
        cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout << "Invalid incident ID.\n"; return;
    }
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    auto it = find_if(incidents.begin(), incidents.end(), [id](const Incident& item) { return item.id == id; });
    if (it == incidents.end()) { cout << "Incident ID not found.\n"; return; }

    cout << "\nSelected incident: " << it->type << " | " << it->severity
         << " | Current status: " << it->status << '\n'
         << "1. Mark as INVESTIGATING\n"
         << "2. Mark as CONTAINED (simulation only)\n"
         << "3. Mark as RESOLVED\n"
         << "0. Cancel\nChoose response: ";
    int choice;
    if (!(cin >> choice)) {
        cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout << "Invalid response choice.\n"; return;
    }
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    if (choice == 0) { cout << "No changes made.\n"; return; }
    string newStatus, action;
    if (choice == 1) { newStatus = "INVESTIGATING"; action = "Analyst review started"; }
    else if (choice == 2) { newStatus = "CONTAINED_SIMULATED"; action = "Simulated containment recorded; no real account or system was changed"; }
    else if (choice == 3) { newStatus = "RESOLVED"; action = "Analyst marked incident resolved"; }
    else { cout << "Invalid response choice.\n"; return; }

    ofstream file(filename, ios::trunc);
    if (!file.is_open()) { cout << "Could not update incident file.\n"; return; }
    for (Incident& item : incidents) {
        if (item.id == id) { item.status = newStatus; item.responseAction = action; }
        file << item.id << " | " << cleanField(item.timestamp) << " | " << cleanField(item.username)
             << " | " << cleanField(item.type) << " | " << cleanField(item.severity) << " | "
             << item.sourceEventID << " | " << cleanField(item.status) << " | "
             << cleanField(item.responseAction) << '\n';
    }
    file.close();
    if (file.good()) {
        logger.logEvent(it->username, "SecurityAnalyst", "INCIDENT_RESPONSE", newStatus + "_INCIDENT_" + to_string(id));
        cout << "Incident #" << id << " updated to " << newStatus << ".\n";
        if (choice == 2) cout << "Note: containment is simulated only; no real system action was performed.\n";
    } else cout << "An error occurred while saving the incident update.\n";
}

void IncidentResponseEngine::runMenu() {
    int choice = -1;
    do {
        cout << "\n========== VIGILX INCIDENT RESPONSE ==========\n"
             << "1. Detect Threats and Create Incidents\n"
             << "2. View Incident Register\n"
             << "3. Update Incident Status / Response\n"
             << "0. Return to Main Menu\n"
             << "==============================================\nChoose option: ";
        if (!(cin >> choice)) {
            cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input.\n"; continue;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        switch (choice) {
            case 1: detectAndCreateIncidents(); break;
            case 2: viewIncidents(); break;
            case 3: updateIncidentStatus(); break;
            case 0: cout << "Returning to main menu.\n"; break;
            default: cout << "Invalid choice.\n"; break;
        }
    } while (choice != 0);
}
