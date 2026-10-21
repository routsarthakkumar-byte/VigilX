#include "ResponsePlaybookEngine.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <algorithm>
using namespace std;
ResponsePlaybookEngine::ResponsePlaybookEngine(SecurityLogger& securityLogger):logger(securityLogger){}
void ResponsePlaybookEngine::showPlaybooks() const {
 cout << "\n========== SIMULATED RESPONSE PLAYBOOKS ==========\n"
      << "PB-01 Repeated failed logins: review account, verify identity, recommend admin unlock only after review.\n"
      << "PB-02 Repeated access denials: review role and resource permissions.\n"
      << "PB-03 High-risk assessment + threat simulation: open analyst review and preserve event IDs.\n"
      << "PB-04 Inactive/locked account access: verify account state and review authentication events.\n"
      << "All actions are recommendations/simulations; no account or external system is automatically blocked.\n";
}
void ResponsePlaybookEngine::evaluateAndSimulate(const string& actor,const string& role) {
 auto logs=logger.readLogs(); map<string,vector<string>> failed,denied,high,threat,locked;
 for(const auto& f:logs){if(f.size()<6)continue; const string& id=f[0];const string& u=f[2];const string& a=f[4];const string& r=f[5];
  if(a=="LOGIN"&&r.find("FAILED")==0)failed[u].push_back(id);
  if(a.find("RESOURCE_ACCESS")==0&&r.find("DENIED")==0)denied[u].push_back(id);
  if(a.find("RISK_ASSESSMENT")==0&&r.find("HIGH")!=string::npos)high[u].push_back(id);
  if(a.find("THREAT_")==0||a=="THREAT_SIMULATION")threat[u].push_back(id);
  if(r.find("ACCOUNT_LOCKED")!=string::npos)locked[u].push_back(id);
 }
 ofstream out("response_playbook_report.txt",ios::trunc);if(!out){cout<<"Could not create report.\n";return;}
 out<<"VIGILX SIMULATED RESPONSE PLAYBOOK REPORT\n"<<"This report recommends actions only; no real containment is performed.\n\n";
 int findings=0;
 auto write=[&](const string& id,const string& u,const string& sev,const string& title,const vector<string>& evidence,const string& action){out<<id<<" | "<<sev<<" | User: "<<u<<" | "<<title<<"\nEvidence event IDs: ";for(size_t i=0;i<evidence.size();++i){if(i)out<<",";out<<evidence[i];}out<<"\nRecommended response: "<<action<<"\n\n";++findings;};
 for(const auto& p:failed)if(p.second.size()>=3)write("PB-01",p.first,"HIGH","Repeated failed logins",p.second,"Review identity and account status; do not unlock without verification.");
 for(const auto& p:denied)if(p.second.size()>=3)write("PB-02",p.first,"MEDIUM","Repeated access denials",p.second,"Review role, custom permissions and requested resource classification.");
 for(const auto& p:high)if(threat.count(p.first)) {auto ev=p.second;ev.insert(ev.end(),threat[p.first].begin(),threat[p.first].end());write("PB-03",p.first,"CRITICAL","High-risk assessment with threat simulation",ev,"Preserve evidence and open an analyst investigation.");}
 for(const auto& p:locked)write("PB-04",p.first,"HIGH","Locked account activity",p.second,"Verify user identity and review authentication history.");
 if(!findings)out<<"No playbook conditions matched current local logs.\n";
 out<<"Total findings: "<<findings<<"\n";out.close();
 logger.logEvent(actor,role,"RESPONSE_PLAYBOOK_SIMULATION","SUCCESS_FINDINGS_"+to_string(findings));
 cout<<"Playbook evaluation complete. Findings: "<<findings<<"\nReport: response_playbook_report.txt\nNo real containment/blocking was performed.\n";
}
void ResponsePlaybookEngine::exportReport() const {ifstream in("response_playbook_report.txt");if(!in){cout<<"Run evaluation first.\n";return;}ofstream out("response_playbook_report_copy.txt",ios::trunc);out<<in.rdbuf();cout<<(out?"Report copy saved to response_playbook_report_copy.txt.\n":"Could not export report.\n");}
void ResponsePlaybookEngine::runMenu(const string& username,const string& role){if(role!="Admin"&&role!="SecurityAnalyst"){cout<<"Access denied: Admin or SecurityAnalyst required.\n";logger.logEvent(username,role,"RESPONSE_PLAYBOOK","DENIED_NOT_AUTHORIZED");return;}int c;do{cout<<"\n===== AUTOMATED RESPONSE PLAYBOOKS (SIMULATED) =====\n1. View Playbooks\n2. Evaluate Logs and Simulate Recommended Response\n3. Export/Copy Latest Report\n0. Return\nChoice: ";if(!(cin>>c)){cin.clear();cin.ignore(100000,'\n');cout<<"Invalid input.\n";continue;}cin.ignore(100000,'\n');switch(c){case 1:showPlaybooks();break;case 2:evaluateAndSimulate(username,role);break;case 3:exportReport();break;case 0:break;default:cout<<"Invalid choice.\n";}}while(c!=0);}
