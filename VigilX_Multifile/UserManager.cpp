#include "UserManager.h"
#include "SecurityLogger.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#include <limits>
#include <algorithm>
using namespace std;
UserManager::UserManager(SecurityLogger& securityLogger):logger(securityLogger){loadUsers();}
void UserManager::saveUsers() const { ofstream file(filename); if(!file){cout<<"Warning: Could not save users.txt.\n";return;} for(const auto& u:users) file<<u->getUserID()<<" | "<<u->getRole()<<" | "<<cleanField(u->getUsername())<<'\n'; }
void UserManager::loadUsers(){ifstream file(filename);string line;int largest=0;while(getline(file,line)){auto f=splitLine(line);if(f.size()<3)continue;try{int id=stoi(f[0]);if(f[1]=="Admin")users.push_back(make_unique<Admin>(id,f[2]));else if(f[1]=="Employee")users.push_back(make_unique<Employee>(id,f[2]));else if(f[1]=="Guest")users.push_back(make_unique<Guest>(id,f[2]));else continue;largest=max(largest,id);}catch(...){cout<<"Warning: Skipping invalid user record.\n";}}nextUserID=largest+1;}
User* UserManager::findUserByID(int id) const {for(const auto& u:users)if(u->getUserID()==id)return u.get();return nullptr;}
void UserManager::addUser(){string name;int choice;cout<<"Enter username: ";getline(cin,name);name=trim(name);if(name.empty()){cout<<"Username cannot be empty.\n";return;}cout<<"1. Admin\n2. Employee\n3. Guest\nSelect role: ";if(!(cin>>choice)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";return;}cin.ignore(numeric_limits<streamsize>::max(),'\n');if(choice<1||choice>3){cout<<"Invalid role.\n";return;}int id=nextUserID++;if(choice==1)users.push_back(make_unique<Admin>(id,name));else if(choice==2)users.push_back(make_unique<Employee>(id,name));else users.push_back(make_unique<Guest>(id,name));User* u=users.back().get();saveUsers();cout<<"User created and saved successfully.\n";u->display();logger.logEvent(name,u->getRole(),"USER_CREATED","SUCCESS");}
void UserManager::viewUsers() const {if(users.empty()){cout<<"No users found.\n";return;}for(const auto& u:users)u->display();}
void UserManager::searchUser() const {int id;cout<<"Enter User ID: ";if(!(cin>>id)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";return;}cin.ignore(numeric_limits<streamsize>::max(),'\n');User* u=findUserByID(id);if(!u){cout<<"User not found.\n";return;}u->display();u->displayPermissions();}
void UserManager::deleteUser(){int id;cout<<"Enter User ID to delete: ";if(!(cin>>id)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";return;}cin.ignore(numeric_limits<streamsize>::max(),'\n');for(auto it=users.begin();it!=users.end();++it)if((*it)->getUserID()==id){string name=(*it)->getUsername(),role=(*it)->getRole();users.erase(it);saveUsers();logger.logEvent(name,role,"USER_DELETED","SUCCESS");cout<<"User deleted and changes saved.\n";return;}cout<<"User not found.\n";}
