#include "UserBehaviorAnalytics.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <map>
#include <limits>
#include <algorithm>

using namespace std;

namespace {
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
        if (c == '\"') result += '\"';
        result += c;
    }
    result += '\"';
    return result;
}
}

UserBehaviorAnalytics::UserBehaviorAnalytics(SecurityLogger& securityLogger) : logger(securityLogger) {}

vector<BehaviorProfile> UserBehaviorAnalytics::analyze() const {
    map<string, BehaviorProfile> byUser;
    for (const auto& fields : logger.readLogs()) {
        if (fields.size() < 6) continue;
        const string& id = fields[0];
        const string& username = fields[2];
        const string& action = fields[4];
        const string& result = fields[5];
        if (username.empty() || username == "SYSTEM" || username == "Unauthenticated" || username == "Unknown") continue;
        auto& profile = byUser[username];
        profile.username = username;
        bool relevant = false;
        if (action == "LOGIN" && result == "SUCCESS") {
            ++profile.successfulLogins; relevant = true;
        } else if (action == "LOGIN" && result.find("FAILED") == 0) {
            ++profile.failedLogins; profile.evidenceIDs.push_back(id); relevant = true;
        }
        if (action.find("RESOURCE_ACCESS") == 0) {
            if (result == "GRANTED") ++profile.grantedAccess;
            if (result.find("DENIED") == 0) { ++profile.deniedAccess; profile.evidenceIDs.push_back(id); }
            relevant = true;
        }
        if (action.find("RISK_ASSESSMENT") == 0 && result.find("_HIGH") != string::npos) {
            ++profile.highRiskAssessments; profile.evidenceIDs.push_back(id); relevant = true;
        }
        if (action == "PASSWORD_CHANGE" && result.find("FAILED") == 0) {
            ++profile.failedPasswordChanges; profile.evidenceIDs.push_back(id); relevant = true;
        }
        (void)relevant;
    }

    vector<BehaviorProfile> profiles;
    for (auto& entry : byUser) {
        auto& p = entry.second;
        if (p.failedLogins >= 3) {
            p.riskScore += 30;
            p.reasons.push_back("Repeated failed login attempts (3 or more): +30");
        }
        if (p.failedLogins >= 5) {
            p.riskScore += 15;
            p.reasons.push_back("Very frequent failed logins (5 or more): +15");
        }
        if (p.deniedAccess >= 3) {
            p.riskScore += 20;
            p.reasons.push_back("Repeated denied resource access (3 or more): +20");
        }
        if (p.highRiskAssessments >= 1) {
            p.riskScore += 15;
            p.reasons.push_back("At least one high-risk assessment: +15");
        }
        if (p.highRiskAssessments >= 2) {
            p.riskScore += 10;
            p.reasons.push_back("Multiple high-risk assessments (2 or more): +10");
        }
        if (p.failedPasswordChanges >= 2) {
            p.riskScore += 10;
            p.reasons.push_back("Repeated failed password changes (2 or more): +10");
        }
        if (p.riskScore > 100) p.riskScore = 100;
        if (p.riskScore >= 50) p.riskLevel = "HIGH";
        else if (p.riskScore >= 25) p.riskLevel = "MEDIUM";
        else p.riskLevel = "LOW";
        profiles.push_back(p);
    }
    stable_sort(profiles.begin(), profiles.end(), [](const BehaviorProfile& a, const BehaviorProfile& b) {
        if (a.riskScore != b.riskScore) return a.riskScore > b.riskScore;
        return a.username < b.username;
    });
    return profiles;
}

void UserBehaviorAnalytics::exportReports(const vector<BehaviorProfile>& profiles) const {
    ofstream txt(textReport, ios::trunc);
    ofstream csv(csvReport, ios::trunc);
    if (!txt || !csv) {
        cout << "Could not create behavior reports. Check folder permissions.\n";
        return;
    }
    txt << "VIGILX USER BEHAVIOR ANALYTICS REPORT\n"
        << "Scope: readable events currently present in security_logs.txt\n"
        << "Risk scoring is heuristic; a score is not proof of malicious intent.\n\n";
    csv << "Username,SuccessfulLogins,FailedLogins,GrantedAccess,DeniedAccess,HighRiskAssessments,FailedPasswordChanges,RiskScore,RiskLevel,EvidenceEventIDs,Reasons\n";
    if (profiles.empty()) txt << "No user activity profiles could be built from the available logs.\n";
    for (const auto& p : profiles) {
        txt << "Username: " << p.username << "\n"
            << "Successful logins: " << p.successfulLogins << "\n"
            << "Failed logins: " << p.failedLogins << "\n"
            << "Granted resource access: " << p.grantedAccess << "\n"
            << "Denied resource access: " << p.deniedAccess << "\n"
            << "High-risk assessments: " << p.highRiskAssessments << "\n"
            << "Failed password changes: " << p.failedPasswordChanges << "\n"
            << "Behavior risk score: " << p.riskScore << "/100 (configured heuristic points)\n"
            << "Risk level: " << p.riskLevel << "\n"
            << "Evidence event IDs: " << joinIDs(p.evidenceIDs) << "\n";
        if (p.reasons.empty()) txt << "Reasons: No configured elevated-risk pattern matched.\n";
        else { txt << "Reasons:\n"; for (const auto& reason : p.reasons) txt << "- " << reason << "\n"; }
        txt << "Recommended action: ";
        if (p.riskLevel == "HIGH") txt << "Prioritize analyst review and verify the account owner and related incidents.\n";
        else if (p.riskLevel == "MEDIUM") txt << "Review the listed evidence and confirm whether the activity is expected.\n";
        else txt << "Continue routine monitoring; no elevated configured pattern was found.\n";
        txt << "----------------------------------------\n";

        string reasons;
        for (size_t i = 0; i < p.reasons.size(); ++i) { if (i) reasons += "; "; reasons += p.reasons[i]; }
        csv << csvEscape(p.username) << ',' << p.successfulLogins << ',' << p.failedLogins << ','
            << p.grantedAccess << ',' << p.deniedAccess << ',' << p.highRiskAssessments << ','
            << p.failedPasswordChanges << ',' << p.riskScore << ',' << csvEscape(p.riskLevel) << ','
            << csvEscape(joinIDs(p.evidenceIDs)) << ',' << csvEscape(reasons) << '\n';
    }
    txt.close(); csv.close();
    if (txt.good() && csv.good()) cout << "Reports saved to " << textReport << " and " << csvReport << ".\n";
    else cout << "Warning: an error occurred while writing a behavior report.\n";
}

void UserBehaviorAnalytics::viewSavedReport() const {
    ifstream file(textReport);
    if (!file) { cout << "No saved behavior report found. Run analysis first.\n"; return; }
    cout << "\n========== SAVED USER BEHAVIOR REPORT ==========\n";
    string line; while (getline(file, line)) cout << line << '\n';
    cout << "================================================\n";
}

void UserBehaviorAnalytics::runMenu(const string& username, const string& role) {
    if (role != "Admin" && role != "SecurityAnalyst") {
        cout << "Access denied: only Admin or SecurityAnalyst can run User Behavior Analytics.\n";
        logger.logEvent(username, role, "USER_BEHAVIOR_ANALYTICS", "DENIED_NOT_AUTHORIZED");
        return;
    }
    int choice = -1;
    do {
        cout << "\n========== VIGILX USER BEHAVIOR ANALYTICS ==========\n"
             << "1. Run User Behavior Analysis\n"
             << "2. View Saved Behavior Report\n"
             << "0. Return to Main Menu\n"
             << "====================================================\nChoose option: ";
        if (!(cin >> choice)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n'); cout << "Invalid input.\n"; continue; }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        if (choice == 1) {
            const auto profiles = analyze();
            cout << "\n========== USER BEHAVIOR PROFILES ==========\n";
            if (profiles.empty()) cout << "No user activity profiles could be built from the available logs.\n";
            for (const auto& p : profiles) {
                cout << "Username: " << p.username << " | Risk: " << p.riskLevel << " (score " << p.riskScore << ")\n"
                     << "Logins: " << p.successfulLogins << " successful, " << p.failedLogins << " failed\n"
                     << "Resource access: " << p.grantedAccess << " granted, " << p.deniedAccess << " denied\n"
                     << "High-risk assessments: " << p.highRiskAssessments << " | Failed password changes: " << p.failedPasswordChanges << '\n'
                     << "Evidence event IDs: " << joinIDs(p.evidenceIDs) << '\n';
                if (p.reasons.empty()) cout << "Reason: No configured elevated-risk pattern matched.\n";
                else for (const auto& reason : p.reasons) cout << "Reason: " << reason << '\n';
                cout << "-------------------------------------------\n";
            }
            cout << "Profiles analyzed: " << profiles.size() << '\n';
            exportReports(profiles);
            logger.logEvent(username, role, "USER_BEHAVIOR_ANALYTICS", "SUCCESS_PROFILES_" + to_string(profiles.size()));
        } else if (choice == 2) viewSavedReport();
        else if (choice != 0) cout << "Invalid choice.\n";
    } while (choice != 0);
}
