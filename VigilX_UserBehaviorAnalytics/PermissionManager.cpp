#include "PermissionManager.h"
#include "User.h"
#include "UserManager.h"
#include "ResourceManager.h"
#include "Resource.h"
#include "SecurityLogger.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <limits>
#include <algorithm>
using namespace std;
PermissionManager::PermissionManager(SecurityLogger& securityLogger):logger(securityLogger){loadRules();}
void PermissionManager::loadRules(){ifstream file(filename);string line;while(getline(file,line)){auto f=splitLine(line);if(f.size()<4)continue;try{int id=stoi(f[1]);if(f[2]!="READ"&&f[2]!="WRITE"&&f[2]!="DELETE")continue;if(f[3]!="ALLOW"&&f[3]!="DENY")continue;rules.push_back({f[0],id,f[2],f[3]=="ALLOW"});}catch(...){cout<<"Warning: Skipping invalid permission rule.\n";}}}
void PermissionManager::saveRules() const {ofstream file(filename);if(!file){cout<<"Warning: Could not save permissions.txt.\n";return;}for(const auto& r:rules)file<<cleanField(r.username)<<" | "<<r.resourceID<<" | "<<r.action<<" | "<<(r.allowed?"ALLOW":"DENY")<<'\n';}
bool PermissionManager::isAllowed(const User& user,const Resource& resource,const string& action) const {
    for(auto it=rules.rbegin();it!=rules.rend();++it)if(it->username==user.getUsername()&&it->resourceID==resource.getResourceID()&&it->action==action)return it->allowed;
    string role=user.getRole(),level=resource.getClassification();
    if(role=="Admin")return true;
    if(action=="READ")return role=="Guest"?level=="Public":(role=="Employee"&&(level=="Public"||level=="Internal"));
    if(action=="WRITE")return role=="Employee"&&(level=="Public"||level=="Internal");
    return false;
}
void PermissionManager::runMenu(const User& admin,const UserManager& users,const ResourceManager& resources){
    if(admin.getRole()!="Admin"){cout<<"Access denied: Admin role required.\n";logger.logEvent(admin.getUsername(),admin.getRole(),"PERMISSION_MANAGEMENT","DENIED_NOT_ADMIN");return;}
    int choice;do{cout<<"\n===== ROLE & PERMISSION MANAGEMENT =====\n1. Grant Permission\n2. Revoke Permission (explicit deny)\n3. Remove Custom Rule (return to role defaults)\n4. View Custom Permission Rules\n0. Return\nChoice: ";if(!(cin>>choice)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";continue;}cin.ignore(numeric_limits<streamsize>::max(),'\n');
        if(choice==0)break;
        if(choice==4){if(rules.empty())cout<<"No custom permission rules configured.\n";else for(const auto& r:rules)cout<<"User: "<<r.username<<" | Resource ID: "<<r.resourceID<<" | Action: "<<r.action<<" | Rule: "<<(r.allowed?"ALLOW":"DENY")<<'\n';continue;}
        if(choice<1||choice>3){cout<<"Invalid choice.\n";continue;}
        int uid,rid;string action;cout<<"Enter target User ID: ";if(!(cin>>uid)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";continue;}cin.ignore(numeric_limits<streamsize>::max(),'\n');
        User* target=users.findUserByID(uid);if(!target){cout<<"User not found.\n";continue;}cout<<"Enter Resource ID: ";if(!(cin>>rid)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";continue;}cin.ignore(numeric_limits<streamsize>::max(),'\n');
        const Resource* resource=resources.findResourceByID(rid);if(!resource){cout<<"Resource not found.\n";continue;}
        cout<<"Action (READ/WRITE/DELETE): ";getline(cin,action);transform(action.begin(),action.end(),action.begin(),[](unsigned char c){return static_cast<char>(toupper(c));});if(action!="READ"&&action!="WRITE"&&action!="DELETE"){cout<<"Invalid action.\n";continue;}
        auto it=find_if(rules.begin(),rules.end(),[&](const Rule& r){return r.username==target->getUsername()&&r.resourceID==rid&&r.action==action;});
        if(choice==3){if(it==rules.end()){cout<<"No matching custom rule exists.\n";continue;}rules.erase(remove_if(rules.begin(),rules.end(),[&](const Rule& r){return r.username==target->getUsername()&&r.resourceID==rid&&r.action==action;}),rules.end());saveRules();logger.logEvent(admin.getUsername(),admin.getRole(),"PERMISSION_RULE_REMOVED","SUCCESS_USER_"+target->getUsername()+"_RESOURCE_"+to_string(rid)+"_"+action);cout<<"Custom rule removed; role-based defaults now apply.\n";continue;}
        bool allow=choice==1;if(it==rules.end())rules.push_back({target->getUsername(),rid,action,allow});else it->allowed=allow;saveRules();string outcome=allow?"GRANTED":"REVOKED_DENY_RULE";logger.logEvent(admin.getUsername(),admin.getRole(),"PERMISSION_"+(allow?string("GRANTED"):string("REVOKED")),"SUCCESS_USER_"+target->getUsername()+"_RESOURCE_"+to_string(rid)+"_"+action);cout<<"Custom rule saved: "<<target->getUsername()<<" / resource "<<rid<<" / "<<action<<" => "<<(allow?"ALLOW":"DENY")<<".\n";
    }while(true);
}
