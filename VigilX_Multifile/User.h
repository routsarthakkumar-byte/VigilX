#pragma once
#include <string>
class User {
private:
    int userID; std::string username; bool active;
public:
    User(int id, const std::string& name);
    virtual ~User() = default;
    int getUserID() const; std::string getUsername() const; bool isActive() const; void deactivate();
    virtual std::string getRole() const = 0;
    virtual void displayPermissions() const = 0;
    void display() const;
};
class Admin : public User {
public: Admin(int id, const std::string& name); std::string getRole() const override; void displayPermissions() const override;
};
class Employee : public User {
public: Employee(int id, const std::string& name); std::string getRole() const override; void displayPermissions() const override;
};
class Guest : public User {
public: Guest(int id, const std::string& name); std::string getRole() const override; void displayPermissions() const override;
};
