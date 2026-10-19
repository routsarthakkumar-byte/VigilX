#include "User.h"
#include <iostream>
using namespace std;
User::User(int id, const string& name) : userID(id), username(name), active(true) {}
int User::getUserID() const { return userID; }
string User::getUsername() const { return username; }
bool User::isActive() const { return active; }
void User::deactivate() { active = false; }
void User::display() const { cout << "\nUser ID  : " << userID << "\nUsername : " << username << "\nRole     : " << getRole() << "\nStatus   : " << (active ? "Active" : "Inactive") << '\n'; }
Admin::Admin(int id, const string& name) : User(id, name) {}
string Admin::getRole() const { return "Admin"; }
void Admin::displayPermissions() const { cout << "Admin permissions: All resource classifications.\n"; }
Employee::Employee(int id, const string& name) : User(id, name) {}
string Employee::getRole() const { return "Employee"; }
void Employee::displayPermissions() const { cout << "Employee permissions: Public and Internal resources.\n"; }
Guest::Guest(int id, const string& name) : User(id, name) {}
string Guest::getRole() const { return "Guest"; }
void Guest::displayPermissions() const { cout << "Guest permissions: Public resources only.\n"; }
