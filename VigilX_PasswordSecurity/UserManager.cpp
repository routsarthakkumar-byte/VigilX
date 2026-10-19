#include "UserManager.h"
#include "SecurityLogger.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <limits>
#include <algorithm>
using namespace std;
UserManager::UserManager(SecurityLogger& securityLogger):logger(securityLogger){loadUsers();}
void UserManager::saveUsers() const {
    ofstream file(filename);
    if(!file){cout<<"Warning: Could not save users.txt.\n";return;}
    for(const auto& u:users) file<<u->getUserID()<<" | "<<u->getRole()<<" | "<<cleanField(u->getUsername())<<" | "<<u->getPasswordSalt()<<" | "<<u->getPasswordHash()<<" | "<<u->getFailedAttempts()<<" | "<<(u->isLocked()?1:0)<<" | "<<(u->getMustChangePassword()?1:0)<<'\n';
}
void UserManager::saveChanges() const { saveUsers(); }
void UserManager::loadUsers(){
    ifstream file(filename); string line; int largest=0;
    while(getline(file,line)){
        auto f=splitLine(line); if(f.size()<3)continue;
        try{
            int id=stoi(f[0]); unique_ptr<User> u;
            if(f[1]=="Admin")u=make_unique<Admin>(id,f[2]);else if(f[1]=="Employee")u=make_unique<Employee>(id,f[2]);else if(f[1]=="Guest")u=make_unique<Guest>(id,f[2]);else continue;
            if(f.size()>=8){int attempts=stoi(f[5]);bool locked=stoi(f[6])!=0;bool needsChange=stoi(f[7])!=0;u->loadPasswordData(f[3],f[4],attempts,locked,needsChange);}
            else u->loadPasswordData("","",0,false,true);
            users.push_back(move(u)); largest=max(largest,id);
        }catch(...){cout<<"Warning: Skipping invalid user record.\n";}
    }
    nextUserID=largest+1;
}
User* UserManager::findUserByID(int id) const {for(const auto& u:users)if(u->getUserID()==id)return u.get();return nullptr;}
void UserManager::addUser(){
    string name,password,confirm;int choice;
    cout<<"Enter username: ";getline(cin,name);name=trim(name);
    if(name.empty()){cout<<"Username cannot be empty.\n";return;}
    for(const auto& existing:users) if(existing->getUsername()==name){cout<<"Username already exists. Choose another username.\n";return;}
    cout<<"1. Admin\n2. Employee\n3. Guest\nSelect role: ";
    if(!(cin>>choice)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";return;}
    cin.ignore(numeric_limits<streamsize>::max(),'\n');if(choice<1||choice>3){cout<<"Invalid role.\n";return;}
    cout<<"Create password (minimum 8 characters): ";getline(cin,password);
    if(password.size()<8){cout<<"Password must contain at least 8 characters. User not created.\n";return;}
    cout<<"Confirm password: ";getline(cin,confirm);if(password!=confirm){cout<<"Passwords do not match. User not created.\n";return;}
    int id=nextUserID++;if(choice==1)users.push_back(make_unique<Admin>(id,name));else if(choice==2)users.push_back(make_unique<Employee>(id,name));else users.push_back(make_unique<Guest>(id,name));
    User* u=users.back().get();u->setPassword(password);saveUsers();cout<<"User created and saved successfully.\n";u->display();logger.logEvent(name,u->getRole(),"USER_CREATED","SUCCESS");
}
void UserManager::viewUsers() const {if(users.empty()){cout<<"No users found.\n";return;}for(const auto& u:users)u->display();}
void UserManager::searchUser() const {int id;cout<<"Enter User ID: ";if(!(cin>>id)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";return;}cin.ignore(numeric_limits<streamsize>::max(),'\n');User* u=findUserByID(id);if(!u){cout<<"User not found.\n";return;}u->display();u->displayPermissions();}
void UserManager::deleteUser(){int id;cout<<"Enter User ID to delete: ";if(!(cin>>id)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";return;}cin.ignore(numeric_limits<streamsize>::max(),'\n');for(auto it=users.begin();it!=users.end();++it)if((*it)->getUserID()==id){string name=(*it)->getUsername(),role=(*it)->getRole();users.erase(it);saveUsers();logger.logEvent(name,role,"USER_DELETED","SUCCESS");cout<<"User deleted and changes saved.\n";return;}cout<<"User not found.\n";}
void UserManager::unlockUserAccount(){int id;cout<<"Enter User ID to unlock: ";if(!(cin>>id)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";return;}cin.ignore(numeric_limits<streamsize>::max(),'\n');User* u=findUserByID(id);if(!u){cout<<"User not found.\n";return;}if(!u->isLocked()){cout<<"This account is already unlocked.\n";return;}u->unlockAccount();saveUsers();logger.logEvent(u->getUsername(),u->getRole(),"ACCOUNT_UNLOCKED","SUCCESS");cout<<"Account unlocked and failed-attempt counter reset.\n";}
