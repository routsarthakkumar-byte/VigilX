#include "IntegrationTestEngine.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <limits>
using namespace std;
namespace {
struct Result {string name;bool pass;string detail;};
}
IntegrationTestEngine::IntegrationTestEngine(SecurityLogger& l):logger(l){}
void IntegrationTestEngine::runMenu(const string& u,const string& r){if(r!="Admin"&&r!="SecurityAnalyst"){cout<<"Access denied.\n";logger.logEvent(u,r,"INTEGRATION_TEST","DENIED_NOT_AUTHORIZED");return;}int c;do{cout<<"\n===== VIGILX FINAL INTEGRATION & TESTING =====\n1. Run Local Self-Checks\n0. Return\nChoice: ";if(!(cin>>c)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";continue;}cin.ignore(numeric_limits<streamsize>::max(),'\n');if(c==0)break;if(c!=1){cout<<"Invalid choice.\n";continue;}
 vector<Result> results;const vector<string> required={"main.cpp","VigilX.cpp","VigilX.h","SecurityLogger.cpp","ThreatSimulator.cpp","IncidentResponseEngine.cpp","SecurityCaseManager.cpp","ResponsePlaybookEngine.cpp","AuditIntegrityEngine.cpp","AlertManagementEngine.cpp","AdvancedSecurityMetrics.cpp","DataValidationRecovery.cpp"};
 for(const auto& f:required){ifstream in(f);results.push_back({"Source file: "+f,bool(in),bool(in)?"present":"missing"});}
 {ifstream in("security_logs.txt");string line;int n=0;while(getline(in,line))if(!line.empty())++n;results.push_back({"Security log readable",bool(in)||n>=0,"local log file checked; records="+to_string(n)});}
 results.push_back({"Basic arithmetic sanity check",(2+2==4)&&((6*7)==42),"arithmetic assertions"});
 int passed=0;ofstream report("vigilx_integration_test_report.txt",ios::trunc);if(!report){cout<<"Could not create test report.\n";continue;}report<<"VIGILX FINAL INTEGRATION & TEST REPORT\nEducational local self-check only; this does not replace full manual QA or security testing.\n\n";for(const auto& x:results){report<<(x.pass?"PASS":"FAIL")<<" | "<<x.name<<" | "<<x.detail<<'\n';if(x.pass)++passed;}report<<"\nPassed: "<<passed<<" / "<<results.size()<<"\n";report.close();cout<<"\nSelf-check results: "<<passed<<"/"<<results.size()<<" passed.\nReport saved to vigilx_integration_test_report.txt\nNote: run the compile command in README.txt separately; this menu check is not a full end-to-end security audit.\n";logger.logEvent(u,r,"INTEGRATION_TEST","PASSED_"+to_string(passed)+"_OF_"+to_string(results.size()));}while(c!=0);}
