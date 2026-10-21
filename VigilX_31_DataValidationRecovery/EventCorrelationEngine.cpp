#include "EventCorrelationEngine.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <algorithm>
#include <limits>

using namespace std;

namespace {
struct UserEvidence {
    vector<string> failedLoginIDs;
    vector<string> deniedAccessIDs;
    vector<string> highRiskIDs;
    vector<string> simulatedThreatIDs;
};

string joinIDs(const vector<string>& ids) {
    if (ids.empty()) return "none";
    string result;
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i) result += ",";
        result += "#" + ids[i];
    }
    return result;
}

string csvEscape(const string& value) {
    string result = "\"";
    for (char c : value) {
        if (c == '"') result += '"';
        result += c;
    }
    result += '"';
    return result;
}

int severityRank(const string& severity) {
    if (severity == "CRITICAL") return 4;
    if (severity == "HIGH") return 3;
    if (severity == "MEDIUM") return 2;
    return 1;
}
}

EventCorrelationEngine::EventCorrelationEngine(SecurityLogger& securityLogger) : logger(securityLogger) {}

vector<CorrelationFinding> EventCorrelationEngine::correlate() const {
    map<string, UserEvidence> evidenceByUser;
    const auto logs = logger.readLogs();

    for (const auto& fields : logs) {
        if (fields.size() < 6) continue;
        const string& eventID = fields[0];
        const string& username = fields[2];
        const string& action = fields[4];
        const string& result = fields[5];
        UserEvidence& evidence = evidenceByUser[username];

        if (action == "LOGIN" && result.find("FAILED") == 0)
            evidence.failedLoginIDs.push_back(eventID);
        if (action.find("RESOURCE_ACCESS") == 0 && result.find("DENIED") == 0)
            evidence.deniedAccessIDs.push_back(eventID);
        if (action.find("RISK_ASSESSMENT") == 0 && result.find("_HIGH") != string::npos)
            evidence.highRiskIDs.push_back(eventID);
        if (action.find("THREAT_SIMULATION:") == 0)
            evidence.simulatedThreatIDs.push_back(eventID);
    }

    vector<CorrelationFinding> findings;
    for (const auto& entry : evidenceByUser) {
        const string& username = entry.first;
        const UserEvidence& evidence = entry.second;
        if (evidence.failedLoginIDs.size() >= 3) {
            findings.push_back({username, "HIGH", "Repeated authentication failures",
                "Failed login events: " + joinIDs(evidence.failedLoginIDs),
                "Review account activity and confirm whether the owner initiated these attempts."});
        }
        if (!evidence.failedLoginIDs.empty() && !evidence.deniedAccessIDs.empty()) {
            findings.push_back({username, "HIGH", "Authentication failures followed by access denials",
                "Failed logins: " + joinIDs(evidence.failedLoginIDs) + "; denied access: " + joinIDs(evidence.deniedAccessIDs),
                "Review the related events together and verify the user's legitimate access needs."});
        }
        if (!evidence.highRiskIDs.empty() && !evidence.simulatedThreatIDs.empty()) {
            findings.push_back({username, "CRITICAL", "High-risk assessment correlated with simulated threat activity",
                "High-risk events: " + joinIDs(evidence.highRiskIDs) + "; simulated threats: " + joinIDs(evidence.simulatedThreatIDs),
                "Inspect the incident register and document an analyst decision before resolving related incidents."});
        }
        if (evidence.deniedAccessIDs.size() >= 3) {
            findings.push_back({username, "MEDIUM", "Repeated resource access denials",
                "Denied access events: " + joinIDs(evidence.deniedAccessIDs),
                "Verify the resource classification, role defaults and custom permission rules."});
        }
    }

    stable_sort(findings.begin(), findings.end(), [](const CorrelationFinding& a, const CorrelationFinding& b) {
        if (severityRank(a.severity) != severityRank(b.severity))
            return severityRank(a.severity) > severityRank(b.severity);
        if (a.username != b.username) return a.username < b.username;
        return a.pattern < b.pattern;
    });
    return findings;
}

void EventCorrelationEngine::exportReports(const vector<CorrelationFinding>& findings) const {
    ofstream textFile(textReport, ios::trunc);
    ofstream csvFile(csvReport, ios::trunc);
    if (!textFile || !csvFile) {
        cout << "Could not create correlation reports. Check folder permissions.\n";
        return;
    }
    textFile << "VIGILX EVENT CORRELATION REPORT\n"
             << "Scope: all readable events currently present in security_logs.txt\n"
             << "Note: correlations are heuristic indicators, not proof of an attack.\n\n";
    csvFile << "Username,Severity,Pattern,Evidence,Recommendation\n";
    if (findings.empty()) textFile << "No configured correlation patterns matched the available logs.\n";
    for (size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        textFile << "Finding " << (i + 1) << "\nUsername: " << f.username
                 << "\nSeverity: " << f.severity << "\nPattern: " << f.pattern
                 << "\nEvidence: " << f.evidence << "\nRecommendation: " << f.recommendation
                 << "\n----------------------------------------\n";
        csvFile << csvEscape(f.username) << ',' << csvEscape(f.severity) << ','
                << csvEscape(f.pattern) << ',' << csvEscape(f.evidence) << ','
                << csvEscape(f.recommendation) << '\n';
    }
    textFile.close(); csvFile.close();
    if (textFile.good() && csvFile.good())
        cout << "Reports saved to " << textReport << " and " << csvReport << ".\n";
    else cout << "Warning: an error occurred while writing a report.\n";
}

void EventCorrelationEngine::viewSavedReport() const {
    ifstream file(textReport);
    if (!file) {
        cout << "No saved correlation report found. Run correlation analysis first.\n";
        return;
    }
    cout << "\n========== SAVED EVENT CORRELATION REPORT ==========\n";
    string line;
    while (getline(file, line)) cout << line << '\n';
    cout << "====================================================\n";
}

void EventCorrelationEngine::runMenu(const string& username, const string& role) {
    if (role != "Admin" && role != "SecurityAnalyst") {
        cout << "Access denied: only Admin or SecurityAnalyst can run event correlation.\n";
        logger.logEvent(username, role, "EVENT_CORRELATION", "DENIED_NOT_AUTHORIZED");
        return;
    }
    int choice = -1;
    do {
        cout << "\n========== VIGILX EVENT CORRELATION ==========\n"
             << "1. Run Event Correlation Analysis\n"
             << "2. View Saved Correlation Report\n"
             << "0. Return to Main Menu\n"
             << "==============================================\nChoose option: ";
        if (!(cin >> choice)) {
            cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input.\n"; continue;
        }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        if (choice == 1) {
            const auto findings = correlate();
            cout << "\n========== CORRELATED SECURITY FINDINGS ==========\n";
            if (findings.empty()) cout << "No configured correlation patterns matched the available logs.\n";
            for (size_t i = 0; i < findings.size(); ++i) {
                const auto& f = findings[i];
                cout << "Finding " << (i + 1) << " | " << f.severity << "\n"
                     << "Username: " << f.username << "\nPattern: " << f.pattern
                     << "\nEvidence: " << f.evidence << "\nRecommendation: " << f.recommendation
                     << "\n-----------------------------------------------\n";
            }
            cout << "Total correlated findings: " << findings.size() << '\n';
            exportReports(findings);
            logger.logEvent(username, role, "EVENT_CORRELATION", "SUCCESS_FINDINGS_" + to_string(findings.size()));
        } else if (choice == 2) viewSavedReport();
        else if (choice != 0) cout << "Invalid choice.\n";
    } while (choice != 0);
}
