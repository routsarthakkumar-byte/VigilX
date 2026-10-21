#include "SecurityCaseManager.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <limits>
#include <algorithm>

using namespace std;

namespace {
string csvEscape(const string& value) {
    string result = "\"";
    for (char c : value) {
        if (c == '"') result += '"';
        result += c;
    }
    result += '"';
    return result;
}
int nextCaseID(const vector<SecurityCase>& cases) {
    int highest = 0;
    for (const auto& item : cases) highest = max(highest, item.id);
    return highest + 1;
}
}

SecurityCaseManager::SecurityCaseManager(SecurityLogger& securityLogger) : logger(securityLogger) {}

vector<SecurityCase> SecurityCaseManager::loadCases() const {
    vector<SecurityCase> cases;
    ifstream file(dataFile);
    string line;
    while (getline(file, line)) {
        auto fields = splitLine(line);
        if (fields.size() < 8) continue;
        try {
            SecurityCase item;
            item.id = stoi(fields[0]);
            item.title = fields[1]; item.severity = fields[2]; item.status = fields[3];
            item.owner = fields[4]; item.username = fields[5]; item.evidence = fields[6]; item.notes = fields[7];
            cases.push_back(item);
        } catch (...) { }
    }
    return cases;
}

bool SecurityCaseManager::saveCases(const vector<SecurityCase>& cases) const {
    ofstream file(dataFile, ios::trunc);
    if (!file) return false;
    for (const auto& item : cases) {
        file << item.id << '|' << cleanField(item.title) << '|' << item.severity << '|'
             << item.status << '|' << cleanField(item.owner) << '|' << cleanField(item.username)
             << '|' << cleanField(item.evidence) << '|' << cleanField(item.notes) << '\n';
    }
    return static_cast<bool>(file);
}

void SecurityCaseManager::createCase(const string& actor, const string& role) {
    vector<SecurityCase> cases = loadCases();
    SecurityCase item;
    item.id = nextCaseID(cases);
    string input;
    cout << "Case title: "; getline(cin, input); item.title = cleanField(trim(input));
    if (item.title.empty()) { cout << "Title cannot be empty.\n"; return; }
    cout << "Severity (LOW/MEDIUM/HIGH/CRITICAL): "; getline(cin, input); input = trim(input);
    transform(input.begin(), input.end(), input.begin(), [](unsigned char c){ return static_cast<char>(toupper(c)); });
    if (input != "LOW" && input != "MEDIUM" && input != "HIGH" && input != "CRITICAL") {
        cout << "Invalid severity. Case not created.\n"; return;
    }
    item.severity = input;
    cout << "Related username (or N/A): "; getline(cin, input); item.username = cleanField(trim(input));
    cout << "Evidence event IDs (e.g. 12,15 or N/A): "; getline(cin, input); item.evidence = cleanField(trim(input));
    cout << "Assigned analyst username: "; getline(cin, input); item.owner = cleanField(trim(input));
    if (item.owner.empty()) item.owner = actor;
    item.status = "OPEN";
    cout << "Initial investigation note (or N/A): "; getline(cin, input); item.notes = cleanField(trim(input));
    cases.push_back(item);
    if (!saveCases(cases)) { cout << "Could not save case. Check folder permissions.\n"; return; }
    cout << "Case #" << item.id << " created successfully.\n";
    logger.logEvent(actor, role, "SECURITY_CASE_CREATE", "SUCCESS_CASE_" + to_string(item.id));
}

void SecurityCaseManager::viewCases() const {
    const auto cases = loadCases();
    if (cases.empty()) { cout << "No security cases found. Create a case first.\n"; return; }
    cout << "\n========== SECURITY CASE REGISTER ==========\n";
    for (const auto& item : cases) {
        cout << "Case ID: " << item.id << "\nTitle: " << item.title << "\nSeverity: " << item.severity
             << "\nStatus: " << item.status << "\nAssigned analyst: " << item.owner
             << "\nRelated username: " << item.username << "\nEvidence IDs: " << item.evidence
             << "\nInvestigation notes: " << item.notes << "\n-------------------------------------------\n";
    }
}

void SecurityCaseManager::updateStatus(const string& actor, const string& role) {
    auto cases = loadCases();
    if (cases.empty()) { cout << "No cases available to update.\n"; return; }
    int id;
    cout << "Enter Case ID: ";
    if (!(cin >> id)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n'); cout << "Invalid ID.\n"; return; }
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    auto it = find_if(cases.begin(), cases.end(), [id](const SecurityCase& item){ return item.id == id; });
    if (it == cases.end()) { cout << "Case not found.\n"; return; }
    cout << "Choose status: 1.OPEN  2.INVESTIGATING  3.CONTAINED_SIMULATED  4.RESOLVED  5.CLOSED\nChoice: ";
    int choice;
    if (!(cin >> choice)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n'); cout << "Invalid choice.\n"; return; }
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    const string statuses[] = {"", "OPEN", "INVESTIGATING", "CONTAINED_SIMULATED", "RESOLVED", "CLOSED"};
    if (choice < 1 || choice > 5) { cout << "Invalid status choice.\n"; return; }
    it->status = statuses[choice];
    if (!saveCases(cases)) { cout << "Could not update case file.\n"; return; }
    cout << "Case #" << id << " status updated to " << it->status << ".\n";
    logger.logEvent(actor, role, "SECURITY_CASE_STATUS", "SUCCESS_CASE_" + to_string(id) + "_" + it->status);
}

void SecurityCaseManager::addInvestigationNote(const string& actor, const string& role) {
    auto cases = loadCases();
    if (cases.empty()) { cout << "No cases available.\n"; return; }
    int id;
    cout << "Enter Case ID: ";
    if (!(cin >> id)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n'); cout << "Invalid ID.\n"; return; }
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    auto it = find_if(cases.begin(), cases.end(), [id](const SecurityCase& item){ return item.id == id; });
    if (it == cases.end()) { cout << "Case not found.\n"; return; }
    string note;
    cout << "Enter investigation note: "; getline(cin, note); note = cleanField(trim(note));
    if (note.empty()) { cout << "Note cannot be empty.\n"; return; }
    if (it->notes.empty() || it->notes == "N/A") it->notes = note;
    else it->notes += " ; " + note;
    if (!saveCases(cases)) { cout << "Could not save note.\n"; return; }
    cout << "Investigation note saved.\n";
    logger.logEvent(actor, role, "SECURITY_CASE_NOTE", "SUCCESS_CASE_" + to_string(id));
}

void SecurityCaseManager::exportReport() const {
    const auto cases = loadCases();
    ofstream textFile(textReport, ios::trunc);
    ofstream csvFile(csvReport, ios::trunc);
    if (!textFile || !csvFile) { cout << "Could not create case reports. Check folder permissions.\n"; return; }
    textFile << "VIGILX SECURITY CASE MANAGEMENT REPORT\n"
             << "Scope: locally saved investigation cases. Containment labels are simulated workflow statuses.\n\n";
    csvFile << "CaseID,Title,Severity,Status,AssignedAnalyst,RelatedUsername,EvidenceEventIDs,InvestigationNotes\n";
    for (const auto& item : cases) {
        textFile << "Case #" << item.id << "\nTitle: " << item.title << "\nSeverity: " << item.severity
                 << "\nStatus: " << item.status << "\nAssigned analyst: " << item.owner
                 << "\nRelated username: " << item.username << "\nEvidence event IDs: " << item.evidence
                 << "\nNotes: " << item.notes << "\n----------------------------------------\n";
        csvFile << item.id << ',' << csvEscape(item.title) << ',' << csvEscape(item.severity) << ','
                << csvEscape(item.status) << ',' << csvEscape(item.owner) << ',' << csvEscape(item.username)
                << ',' << csvEscape(item.evidence) << ',' << csvEscape(item.notes) << '\n';
    }
    textFile.close(); csvFile.close();
    if (textFile.good() && csvFile.good()) cout << "Reports saved to " << textReport << " and " << csvReport << ".\n";
    else cout << "Warning: an error occurred while writing report files.\n";
}

void SecurityCaseManager::viewRecentEvents() const {
    const auto logs = logger.readLogs();
    if (logs.empty()) { cout << "No security log events are available.\n"; return; }
    size_t start = logs.size() > 10 ? logs.size() - 10 : 0;
    cout << "\n========== RECENT SECURITY EVENTS =========\n";
    for (size_t i = start; i < logs.size(); ++i) {
        const auto& row = logs[i];
        if (row.size() < 6) continue;
        cout << "Event #" << row[0] << " | User: " << row[2] << " | Action: " << row[4] << " | Result: " << row[5] << '\n';
    }
    cout << "Use these event IDs as case evidence.\n";
}

void SecurityCaseManager::runMenu(const string& username, const string& role) {
    if (role != "Admin" && role != "SecurityAnalyst") {
        cout << "Access denied: only Admin or SecurityAnalyst can manage security cases.\n";
        logger.logEvent(username, role, "SECURITY_CASE_MANAGEMENT", "DENIED_NOT_AUTHORIZED");
        return;
    }
    int choice;
    do {
        cout << "\n========== SECURITY CASE MANAGEMENT ==========\n"
             << "1. Create Investigation Case\n2. View Case Register\n3. Update Case Status\n"
             << "4. Add Investigation Note\n5. View Recent Events for Evidence\n6. Export Case Reports (TXT/CSV)\n0. Return to Main Menu\nChoice: ";
        if (!(cin >> choice)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n'); cout << "Invalid input.\n"; continue; }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        switch (choice) {
            case 1: createCase(username, role); break;
            case 2: viewCases(); break;
            case 3: updateStatus(username, role); break;
            case 4: addInvestigationNote(username, role); break;
            case 5: viewRecentEvents(); break;
            case 6: exportReport(); logger.logEvent(username, role, "SECURITY_CASE_EXPORT", "SUCCESS"); break;
            case 0: break;
            default: cout << "Invalid choice.\n";
        }
    } while (choice != 0);
}
