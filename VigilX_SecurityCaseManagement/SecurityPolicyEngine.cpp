#include "SecurityPolicyEngine.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <map>
#include <algorithm>
#include <limits>
#include <ctime>
#include <iomanip>
#include <sstream>

using namespace std;

namespace {
string currentTimestamp() {
    time_t now = time(nullptr);
    tm* local = localtime(&now);
    if (!local) return "Unknown";
    stringstream ss;
    ss << put_time(local, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}
string csvEscape(const string& value) {
    string out = "\"";
    for (char c : value) {
        if (c == '"') out += '"';
        out += c;
    }
    out += '"';
    return out;
}
}

SecurityPolicyEngine::SecurityPolicyEngine(SecurityLogger& securityLogger) : logger(securityLogger) {
    loadPolicies();
}

void SecurityPolicyEngine::loadPolicies() {
    ifstream file(policyFile);
    string line;
    while (getline(file, line)) {
        auto fields = splitLine(line);
        if (fields.size() < 4) continue;
        try {
            int id = stoi(fields[0]);
            if (fields[3] != "ENABLED" && fields[3] != "DISABLED") continue;
            policies.push_back({id, fields[1], fields[2], fields[3] == "ENABLED"});
        } catch (...) {}
    }
    if (policies.empty()) {
        policies = {
            {1, "Repeated Failed Logins", "A username should not have 3 or more failed login events.", true},
            {2, "Repeated Access Denials", "A username should not have 3 or more denied resource access events.", true},
            {3, "High-Risk Access Assessment", "High-risk resource access assessments must be reviewed.", true},
            {4, "Privileged Action Denials", "Unauthorized attempts to manage roles or permissions must be reviewed.", true},
            {5, "Incident Follow-up", "Detected incidents should not remain OPEN after analyst review.", true}
        };
        savePolicies();
    }
}

void SecurityPolicyEngine::savePolicies() const {
    ofstream file(policyFile, ios::trunc);
    if (!file.is_open()) {
        cout << "Warning: Could not save policies.txt.\n";
        return;
    }
    for (const auto& policy : policies) {
        file << policy.id << " | " << cleanField(policy.name) << " | "
             << cleanField(policy.description) << " | "
             << (policy.enabled ? "ENABLED" : "DISABLED") << '\n';
    }
}

vector<PolicyFinding> SecurityPolicyEngine::evaluatePolicies() const {
    vector<PolicyFinding> findings;
    const auto logs = logger.readLogs();
    map<string, int> failedLogins, deniedAccess;
    bool highRisk = false, privilegedDenied = false;
    string highRiskDetails = "No high-risk assessment events found.";
    string privilegedDetails = "No denied privileged-management attempts found.";
    for (const auto& f : logs) {
        if (f.size() < 6) continue;
        const string& username = f[2];
        const string& action = f[4];
        const string& result = f[5];
        if (action == "LOGIN" && result.find("FAILED") == 0) ++failedLogins[username];
        if (action.find("RESOURCE_ACCESS") == 0 && result.find("DENIED") == 0) ++deniedAccess[username];
        if (action.find("RISK_ASSESSMENT") == 0 && result.find("_HIGH") != string::npos) {
            highRisk = true;
            highRiskDetails = "High-risk assessment found at event #" + f[0] + " for " + username + " (" + result + ").";
        }
        if ((action == "ROLE_MANAGEMENT" || action == "PERMISSION_MANAGEMENT") && result.find("DENIED") == 0) {
            privilegedDenied = true;
            privilegedDetails = "Denied privileged-management attempt at event #" + f[0] + " by " + username + ".";
        }
    }

    for (const auto& p : policies) {
        if (!p.enabled) {
            findings.push_back({p.id, p.name, "DISABLED", "Policy is disabled and was not evaluated.", "Enable this policy if it should be enforced in audits."});
            continue;
        }
        if (p.id == 1) {
            vector<string> violating;
            for (const auto& entry : failedLogins) if (entry.second >= 3) violating.push_back(entry.first + " (" + to_string(entry.second) + " failed logins)");
            findings.push_back({p.id, p.name, violating.empty() ? "PASS" : "FAIL",
                violating.empty() ? "No username has 3 or more failed login events." : "Threshold reached: " + [&](){ string s; for(size_t i=0;i<violating.size();++i){if(i)s += ", ";s += violating[i];}return s;}(),
                violating.empty() ? "Continue monitoring login events." : "Review the account, confirm the owner, and keep locked accounts locked until verified."});
        } else if (p.id == 2) {
            vector<string> violating;
            for (const auto& entry : deniedAccess) if (entry.second >= 3) violating.push_back(entry.first + " (" + to_string(entry.second) + " denials)");
            findings.push_back({p.id, p.name, violating.empty() ? "PASS" : "FAIL",
                violating.empty() ? "No username has 3 or more denied resource access events." : "Repeated denials: " + [&](){ string s; for(size_t i=0;i<violating.size();++i){if(i)s += ", ";s += violating[i];}return s;}(),
                violating.empty() ? "Continue monitoring access decisions." : "Review requested resources and verify role/custom permissions."});
        } else if (p.id == 3) {
            findings.push_back({p.id, p.name, highRisk ? "REVIEW REQUIRED" : "PASS", highRisk ? highRiskDetails : "No high-risk assessment events found.", highRisk ? "Review the associated event and incident register." : "Continue risk monitoring."});
        } else if (p.id == 4) {
            findings.push_back({p.id, p.name, privilegedDenied ? "REVIEW REQUIRED" : "PASS", privilegedDenied ? privilegedDetails : "No denied privileged-management attempts found.", privilegedDenied ? "Confirm the actor lacked authorization and review surrounding logs." : "Keep administrative functions restricted to Admin users."});
        } else if (p.id == 5) {
            ifstream incidentFile("incidents.txt"); string line; int openCount = 0; vector<string> openIDs;
            while (getline(incidentFile, line)) {
                auto f = splitLine(line);
                if (f.size() >= 7 && f[6] == "OPEN") { ++openCount; openIDs.push_back("#" + f[0] + " " + f[3] + " (" + f[4] + ")"); }
            }
            string details = openCount == 0 ? "No OPEN incidents found." : to_string(openCount) + " incident(s) remain OPEN: ";
            for (size_t i=0;i<openIDs.size();++i) { if(i) details += ", "; details += openIDs[i]; }
            findings.push_back({p.id, p.name, openCount == 0 ? "PASS" : "FAIL", details,
                openCount == 0 ? "Continue reviewing newly detected incidents." : "Review each OPEN incident and update its status in Incident Response."});
        } else {
            findings.push_back({p.id, p.name, "NOT EVALUATED", "Unknown policy ID; no evaluator is implemented for this policy.", "Use a supported policy ID or update the policy engine."});
        }
    }
    return findings;
}

void SecurityPolicyEngine::exportAudit(const vector<PolicyFinding>& findings, const string& timestamp) const {
    ofstream txt(auditFile, ios::app);
    if (txt.is_open()) {
        txt << "\nVIGILX SECURITY POLICY AUDIT | " << timestamp << "\n";
        int pass=0, fail=0, review=0, disabled=0;
        for (const auto& f : findings) {
            txt << "Policy #" << f.policyID << " | " << f.policyName << " | " << f.status << "\n"
                << "Details: " << f.details << "\nRecommendation: " << f.recommendation << "\n\n";
            if(f.status=="PASS")++pass; else if(f.status=="FAIL")++fail; else if(f.status=="REVIEW REQUIRED")++review; else if(f.status=="DISABLED")++disabled;
        }
        txt << "Summary: PASS=" << pass << ", FAIL=" << fail << ", REVIEW REQUIRED=" << review << ", DISABLED=" << disabled << "\n"
            << "Note: This is a local educational audit, not a certified compliance assessment.\n"
            << "============================================================\n";
    } else cout << "Warning: Could not append compliance_audit.txt.\n";

    bool needsHeader = false;
    { ifstream existing(csvFile); needsHeader = !existing.good() || existing.peek() == ifstream::traits_type::eof(); }
    ofstream csv(csvFile, ios::app);
    if (!csv.is_open()) { cout << "Warning: Could not append compliance_audit.csv.\n"; return; }
    if (needsHeader) csv << "timestamp,policy_id,policy_name,status,details,recommendation\n";
    for (const auto& f : findings) csv << csvEscape(timestamp) << ',' << f.policyID << ',' << csvEscape(f.policyName) << ',' << csvEscape(f.status) << ',' << csvEscape(f.details) << ',' << csvEscape(f.recommendation) << '\n';
}

void SecurityPolicyEngine::runMenu(const string& username, const string& role) {
    if (role != "Admin") {
        cout << "Access denied: only a logged-in Admin can manage or run policy audits.\n";
        logger.logEvent(username, role, "POLICY_AUDIT", "DENIED_NOT_ADMIN");
        return;
    }
    int choice = -1;
    do {
        cout << "\n========== SECURITY POLICY & COMPLIANCE =========="
             << "\n1. View Security Policies"
             << "\n2. Run Compliance Audit and Export Reports"
             << "\n3. Enable/Disable a Policy"
             << "\n4. View Latest Audit Results"
             << "\n0. Return to Main Menu"
             << "\n===================================================\nChoose option: ";
        if (!(cin >> choice)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n'); cout << "Invalid input.\n"; continue; }
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        if (choice == 1) {
            for (const auto& p : policies) cout << "Policy #" << p.id << " | " << p.name << " | " << (p.enabled ? "ENABLED" : "DISABLED") << "\nDescription: " << p.description << "\n\n";
        } else if (choice == 2) {
            auto findings = evaluatePolicies();
            string timestamp = currentTimestamp();
            int pass=0, fail=0, review=0, disabled=0;
            cout << "\n========== COMPLIANCE AUDIT RESULTS ==========\nAudit time: " << timestamp << '\n';
            for (const auto& f : findings) {
                cout << "\n[" << f.status << "] Policy #" << f.policyID << ": " << f.policyName << "\n"
                     << "Details: " << f.details << "\nRecommendation: " << f.recommendation << '\n';
                if(f.status=="PASS")++pass; else if(f.status=="FAIL")++fail; else if(f.status=="REVIEW REQUIRED")++review; else if(f.status=="DISABLED")++disabled;
            }
            cout << "\nSummary: PASS=" << pass << " | FAIL=" << fail << " | REVIEW REQUIRED=" << review << " | DISABLED=" << disabled << '\n'
                 << "Note: This educational audit does not certify legal/regulatory compliance.\n";
            exportAudit(findings, timestamp);
            logger.logEvent(username, role, "POLICY_AUDIT", "COMPLETED_FAIL_" + to_string(fail) + "_REVIEW_" + to_string(review));
            cout << "Audit saved to compliance_audit.txt and compliance_audit.csv.\n";
        } else if (choice == 3) {
            int id; cout << "Enter policy ID: ";
            if (!(cin >> id)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n'); cout << "Invalid policy ID.\n"; continue; }
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            auto it = find_if(policies.begin(), policies.end(), [id](const SecurityPolicy& p){return p.id==id;});
            if (it == policies.end()) { cout << "Policy ID not found.\n"; continue; }
            cout << "1. Enable\n2. Disable\n0. Cancel\nChoice: "; int state;
            if (!(cin >> state)) { cin.clear(); cin.ignore(numeric_limits<streamsize>::max(), '\n'); cout << "Invalid choice.\n"; continue; }
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            if (state == 0) { cout << "No changes made.\n"; continue; }
            if (state != 1 && state != 2) { cout << "Invalid choice.\n"; continue; }
            it->enabled = state == 1; savePolicies();
            logger.logEvent(username, role, "POLICY_CONFIGURATION", "SUCCESS_POLICY_" + to_string(id) + (it->enabled ? "_ENABLED" : "_DISABLED"));
            cout << "Policy " << id << " is now " << (it->enabled ? "ENABLED" : "DISABLED") << " and saved.\n";
        } else if (choice == 4) {
            ifstream file(auditFile); string line;
            if (!file.is_open()) cout << "No audit report found. Run an audit first.\n";
            else { cout << "\n========== SAVED COMPLIANCE AUDITS ==========" << '\n'; bool any=false; while(getline(file,line)){cout<<line<<'\n';any=true;} if(!any)cout<<"No saved audit reports found.\n"; }
        } else if (choice == 0) cout << "Returning to main menu.\n";
        else cout << "Invalid choice.\n";
    } while (choice != 0);
}
