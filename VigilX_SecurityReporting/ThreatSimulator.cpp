#include "ThreatSimulator.h"
#include "Threat.h"
#include <iostream>
#include <limits>
#include <memory>
using namespace std;
ThreatSimulator::ThreatSimulator(SecurityLogger& securityLogger):logger(securityLogger){}
void ThreatSimulator::runMenu(){
    int choice=-1;
    do{
        cout<<"\n========== VIGILX THREAT SIMULATOR ==========\n"
            <<"Controlled simulations only; no real attacks are performed.\n"
            <<"1. Brute Force Attack\n2. Unauthorized Access\n3. Suspicious Login\n"
            <<"4. Privilege Escalation\n5. Abnormal Resource Access\n6. Custom Scenario\n"
            <<"0. Return to Main Menu\n=============================================\nChoose scenario: ";
        if(!(cin>>choice)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";continue;}
        cin.ignore(numeric_limits<streamsize>::max(),'\n'); unique_ptr<Threat> threat;
        switch(choice){
            case 1:threat=make_unique<BruteForceAttack>(logger);break;
            case 2:threat=make_unique<UnauthorizedAccess>(logger);break;
            case 3:threat=make_unique<SuspiciousLogin>(logger);break;
            case 4:threat=make_unique<PrivilegeEscalation>(logger);break;
            case 5:threat=make_unique<AbnormalResourceAccess>(logger);break;
            case 6:threat=make_unique<CustomThreatScenario>(logger);break;
            case 0:cout<<"Returning to main menu.\n";break;
            default:cout<<"Invalid choice.\n";break;
        }
        if(threat){cout<<"Selected: "<<threat->getName()<<" | Expected severity: "<<threat->getSeverity()<<'\n';threat->simulate();}
    }while(choice!=0);
}
