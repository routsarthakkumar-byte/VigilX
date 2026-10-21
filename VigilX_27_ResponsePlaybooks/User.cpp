#include "User.h"
#include "PasswordUtils.h"
#include <iostream>
using namespace std;
User::User(int id, const string& name) : userID(id), username(name), active(true), failedAttempts(0), locked(false), mustChangePassword(true) {}
int User::getUserID() const { return userID; }
string User::getUsername() const { return username; }
bool User::isActive() const { return active; }
void User::deactivate() { active = false; }
bool User::isLocked() const { return locked; }
int User::getFailedAttempts() const { return failedAttempts; }
bool User::needsPasswordSetup() const { return passwordHash.empty() || mustChangePassword; }
void User::setPassword(const string& password) { passwordSalt = generateSalt(); passwordHash = hashPassword(password, passwordSalt); failedAttempts = 0; locked = false; mustChangePassword = false; }
bool User::verifyPassword(const string& password) const { return !passwordHash.empty() && hashPassword(password, passwordSalt) == passwordHash; }
void User::loadPasswordData(const string& salt, const string& hash, int attempts, bool isLocked, bool needsChange) { passwordSalt=salt; passwordHash=hash; failedAttempts=attempts<0?0:attempts; locked=isLocked; mustChangePassword=needsChange || hash.empty(); }
void User::recordFailedAttempt() { ++failedAttempts; if (failedAttempts >= 3) locked = true; }
void User::resetFailedAttempts() { failedAttempts=0; }
void User::unlockAccount() { locked=false; failedAttempts=0; }
string User::getPasswordSalt() const { return passwordSalt; }
string User::getPasswordHash() const { return passwordHash; }
bool User::getMustChangePassword() const { return mustChangePassword; }
void User::display() const { cout << "\nUser ID  : " << userID << "\nUsername : " << username << "\nRole     : " << getRole() << "\nStatus   : " << (active ? "Active" : "Inactive") << "\nAccount  : " << (locked ? "Locked" : "Unlocked") << '\n'; }
Admin::Admin(int id, const string& name) : User(id, name) {}
string Admin::getRole() const { return "Admin"; }
void Admin::displayPermissions() const { cout << "Admin permissions: All resource classifications.\n"; }
Employee::Employee(int id, const string& name) : User(id, name) {}
string Employee::getRole() const { return "Employee"; }
void Employee::displayPermissions() const { cout << "Employee permissions: Public and Internal resources.\n"; }
Guest::Guest(int id, const string& name) : User(id, name) {}
string Guest::getRole() const { return "Guest"; }
void Guest::displayPermissions() const { cout << "Guest permissions: Public resources only.\n"; }
