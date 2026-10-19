#include "SecurityLogger.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <map>
using namespace std;
SecurityLogger::SecurityLogger() {
    ifstream file(filename); string line; int largestID = 0;
    while (getline(file, line)) { auto fields = splitLine(line); if (!fields.empty()) try { largestID = max(largestID, stoi(fields[0])); } catch (...) {} }
    nextEventID = largestID + 1;
}
void SecurityLogger::logEvent(const string& username,const string& role,const string& action,const string& result) {
    ofstream file(filename, ios::app); if (!file.is_open()) { cout << "Warning: Could not write security log.\n"; return; }
    time_t now = time(nullptr); tm* localTime = localtime(&now); string timestamp = "Unknown";
    if (localTime) { stringstream ss; ss << put_time(localTime, "%Y-%m-%d %H:%M:%S"); timestamp = ss.str(); }
    file << nextEventID << " | " << timestamp << " | " << cleanField(username) << " | " << cleanField(role) << " | " << cleanField(action) << " | " << cleanField(result) << '\n';
    if (file.good()) { cout << "[Security Event #" << nextEventID << " recorded]\n"; ++nextEventID; }
}
vector<vector<string>> SecurityLogger::readLogs() const {
    vector<vector<string>> records; ifstream file(filename); string line;
    while (getline(file,line)) { auto fields=splitLine(line); if(fields.size()>=6) records.push_back(fields); } return records;
}
int SecurityLogger::countPreviousDeniedRequests(const string& username) const {
    int count=0; for(const auto& f:readLogs()) if(f[2]==username && f[4].find("RESOURCE_ACCESS")==0 && f[5].find("DENIED")==0) ++count; return count;
}
void SecurityLogger::viewLogs() const {
    auto records=readLogs(); cout << "\n========== SECURITY LOGS ==========\n";
    if(records.empty()){ cout << "No security events found.\n"; return; }
    for(const auto& f:records){ for(size_t i=0;i<f.size();++i){ if(i) cout << " | "; cout << f[i]; } cout << '\n'; }
    cout << "===================================\n";
}
void SecurityLogger::viewStatistics() const {
    int total=0,loginAttempts=0,successful=0,failed=0,accessRequests=0,granted=0,denied=0,usersCreated=0,usersDeleted=0,resourcesCreated=0,resourcesDeleted=0,riskAssessments=0,highRisk=0,logouts=0;
    for(const auto& f:readLogs()){ ++total; string a=f[4],r=f[5];
        if(a=="LOGIN"){++loginAttempts;if(r=="SUCCESS")++successful;else if(r.find("FAILED")==0)++failed;}
        if(a.find("RESOURCE_ACCESS")==0){++accessRequests;if(r=="GRANTED")++granted;else if(r.find("DENIED")==0)++denied;}
        if(a=="USER_CREATED") ++usersCreated;
        if(a=="USER_DELETED") ++usersDeleted;
        if(a=="RESOURCE_CREATED") ++resourcesCreated;
        if(a=="RESOURCE_DELETED") ++resourcesDeleted;
        if(a=="LOGOUT") ++logouts;
        if(a.find("RISK_ASSESSMENT")==0){++riskAssessments;if(r.find("_HIGH")!=string::npos)++highRisk;}
    }
    cout << "\n====== VIGILX SECURITY STATISTICS ======\n" << "Total Events          : "<<total<<'\n'<<"Login Attempts        : "<<loginAttempts<<'\n'<<"Successful Logins     : "<<successful<<'\n'<<"Failed Logins         : "<<failed<<'\n'<<"Access Requests       : "<<accessRequests<<'\n'<<"Access Granted        : "<<granted<<'\n'<<"Access Denied         : "<<denied<<'\n'<<"Users Created         : "<<usersCreated<<'\n'<<"Users Deleted         : "<<usersDeleted<<'\n'<<"Resources Created     : "<<resourcesCreated<<'\n'<<"Resources Deleted     : "<<resourcesDeleted<<'\n'<<"Risk Assessments      : "<<riskAssessments<<'\n'<<"High-Risk Assessments : "<<highRisk<<'\n'<<"Logout Events         : "<<logouts<<'\n'<<"========================================\n";
}
void SecurityLogger::viewThreatAlerts() const {
    auto records=readLogs(); map<string,int> failedLogins,deniedRequests; int alerts=0;
    for(const auto& f:records){string u=f[2],a=f[4],r=f[5];if(a=="LOGIN"&&r.find("FAILED")==0)++failedLogins[u];if(a.find("RESOURCE_ACCESS")==0&&r.find("DENIED")==0)++deniedRequests[u];}
    cout << "\n========== VIGILX THREAT ALERTS ==========\n";
    for(const auto& e:failedLogins) if(e.second>=3){cout<<"[HIGH] Repeated failed logins\nUsername: "<<e.first<<"\nAttempts: "<<e.second<<"\n\n";++alerts;}
    for(const auto& e:deniedRequests) if(e.second>=3){cout<<"[MEDIUM] Repeated access denials\nUsername: "<<e.first<<"\nDenied requests: "<<e.second<<"\n\n";++alerts;}
    for(const auto& f:records) if(f[4].find("RISK_ASSESSMENT")==0&&f[5].find("_HIGH")!=string::npos){cout<<"[HIGH] High-risk access activity\nEvent ID: "<<f[0]<<"\nUsername: "<<f[2]<<"\nResult: "<<f[5]<<"\n\n";++alerts;}
    if(!alerts) cout<<"No alerts matched the configured rules.\n";
    cout<<"Total matching alerts: "<<alerts<<"\n==========================================\n";
}
