#include "Threat.h"
#include "Utils.h"
#include <iostream>
#include <limits>
using namespace std;

Threat::Threat(SecurityLogger& securityLogger) : logger(securityLogger) {}
string Threat::readTargetUsername() const {
    string value; cout << "Enter target username: "; getline(cin, value); value = trim(value);
    if (value.empty()) cout << "Username cannot be empty. Scenario cancelled.\n";
    return value;
}
string Threat::readTargetResource() const {
    string value; cout << "Enter simulated resource name: "; getline(cin, value); value = trim(value);
    if (value.empty()) cout << "Resource name cannot be empty. Scenario cancelled.\n";
    return value;
}

BruteForceAttack::BruteForceAttack(SecurityLogger& l):Threat(l){}
string BruteForceAttack::getName() const{return "Brute Force Attack";}
string BruteForceAttack::getSeverity() const{return "HIGH";}
void BruteForceAttack::simulate(){
    cout<<"\n--- SIMULATED BRUTE FORCE SCENARIO ---\nThis writes sample failed-login records only; no real logins are attempted.\n";
    string user=readTargetUsername(); if(user.empty())return;
    int n; cout<<"Number of simulated failed attempts (3-10): ";
    if(!(cin>>n)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input. Scenario cancelled.\n";return;}
    cin.ignore(numeric_limits<streamsize>::max(),'\n'); if(n<3||n>10){cout<<"Choose a value from 3 to 10.\n";return;}
    for(int i=1;i<=n;++i) logger.logEvent(user,"Unknown","LOGIN","FAILED_SIMULATED_BRUTE_FORCE");
    logger.logEvent(user,"Unknown","THREAT_SIMULATION:BRUTE_FORCE","HIGH_DETECTED_ATTEMPTS_"+to_string(n));
    cout<<"[HIGH] Scenario recorded. Open option 14 (Threat Alerts) to see the repeated-failure alert.\n";
}

UnauthorizedAccess::UnauthorizedAccess(SecurityLogger& l):Threat(l){}
string UnauthorizedAccess::getName() const{return "Unauthorized Access";}
string UnauthorizedAccess::getSeverity() const{return "HIGH";}
void UnauthorizedAccess::simulate(){
    cout<<"\n--- SIMULATED UNAUTHORIZED ACCESS ---\nThis writes a denied sample event only; no real resource is accessed.\n";
    string user=readTargetUsername();if(user.empty())return; string resource=readTargetResource();if(resource.empty())return;
    logger.logEvent(user,"Unknown","RESOURCE_ACCESS:SIMULATED_UNAUTHORIZED:"+cleanField(resource),"DENIED_SIMULATED");
    logger.logEvent(user,"Unknown","THREAT_SIMULATION:UNAUTHORIZED_ACCESS","HIGH_DETECTED_RESOURCE_"+cleanField(resource));
    cout<<"[HIGH] Unauthorized-access scenario recorded in security logs.\n";
}

SuspiciousLogin::SuspiciousLogin(SecurityLogger& l):Threat(l){}
string SuspiciousLogin::getName() const{return "Suspicious Login";}
string SuspiciousLogin::getSeverity() const{return "MEDIUM";}
void SuspiciousLogin::simulate(){
    cout<<"\n--- SIMULATED SUSPICIOUS LOGIN ---\nThis records one sample failed-login event only.\n";
    string user=readTargetUsername();if(user.empty())return;
    logger.logEvent(user,"Unknown","LOGIN","FAILED_SIMULATED_SUSPICIOUS_LOGIN");
    logger.logEvent(user,"Unknown","THREAT_SIMULATION:SUSPICIOUS_LOGIN","MEDIUM_DETECTED");
    cout<<"[MEDIUM] Suspicious-login scenario recorded.\n";
}

PrivilegeEscalation::PrivilegeEscalation(SecurityLogger& l):Threat(l){}
string PrivilegeEscalation::getName() const{return "Privilege Escalation";}
string PrivilegeEscalation::getSeverity() const{return "CRITICAL";}
void PrivilegeEscalation::simulate(){
    cout<<"\n--- SIMULATED PRIVILEGE ESCALATION ---\nThis models a blocked privilege request. No role or permissions are changed.\n";
    string user=readTargetUsername();if(user.empty())return;
    logger.logEvent(user,"Unknown","THREAT_SIMULATION:PRIVILEGE_ESCALATION","CRITICAL_BLOCKED");
    cout<<"[CRITICAL] Privilege-escalation attempt simulated and blocked.\n";
}

AbnormalResourceAccess::AbnormalResourceAccess(SecurityLogger& l):Threat(l){}
string AbnormalResourceAccess::getName() const{return "Abnormal Resource Access";}
string AbnormalResourceAccess::getSeverity() const{return "HIGH";}
void AbnormalResourceAccess::simulate(){
    cout<<"\n--- SIMULATED ABNORMAL RESOURCE ACCESS ---\nThis creates denied sample events only; no actual resource is accessed.\n";
    string user=readTargetUsername();if(user.empty())return; string resource=readTargetResource();if(resource.empty())return;
    int n;cout<<"Number of simulated denied requests (1-10): ";
    if(!(cin>>n)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input. Scenario cancelled.\n";return;}
    cin.ignore(numeric_limits<streamsize>::max(),'\n');if(n<1||n>10){cout<<"Choose a value from 1 to 10.\n";return;}
    for(int i=1;i<=n;++i)logger.logEvent(user,"Unknown","RESOURCE_ACCESS:SIMULATED_ABNORMAL:"+cleanField(resource),"DENIED_SIMULATED");
    logger.logEvent(user,"Unknown","THREAT_SIMULATION:ABNORMAL_RESOURCE_ACCESS","HIGH_DETECTED_ATTEMPTS_"+to_string(n));
    cout<<"[HIGH] Abnormal-access pattern recorded. Open option 14 (Threat Alerts) to review repeated denials.\n";
}

CustomThreatScenario::CustomThreatScenario(SecurityLogger& l):Threat(l){}
string CustomThreatScenario::getName() const{return "Custom Scenario";}
string CustomThreatScenario::getSeverity() const{return "USER_DEFINED";}
void CustomThreatScenario::simulate(){
    cout<<"\n--- CUSTOM THREAT SCENARIO ---\nSimulation only; no attack is performed.\n";
    string user=readTargetUsername();if(user.empty())return;string scenario;cout<<"Scenario name: ";getline(cin,scenario);scenario=trim(scenario);
    if(scenario.empty()){cout<<"Scenario name cannot be empty.\n";return;}
    int c;cout<<"Severity: 1. LOW  2. MEDIUM  3. HIGH  4. CRITICAL\nChoice: ";
    if(!(cin>>c)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";return;}
    cin.ignore(numeric_limits<streamsize>::max(),'\n');if(c<1||c>4){cout<<"Invalid severity.\n";return;}
    const string levels[]={"LOW","MEDIUM","HIGH","CRITICAL"};
    logger.logEvent(user,"Unknown","THREAT_SIMULATION:CUSTOM:"+cleanField(scenario),levels[c-1]+"_SIMULATED");
    cout<<"["<<levels[c-1]<<"] Custom scenario recorded in security logs.\n";
}
