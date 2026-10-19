
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <limits>
#include <algorithm>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <map>

using namespace std;

string trim(const string& value) {
    size_t start = value.find_first_not_of(" \t\r\n");
    if (start == string::npos) return "";
    size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

string cleanField(string value) {
    for (char& ch : value) {
        if (ch == '|' || ch == '\n' || ch == '\r') ch = '_';
    }
    return value;
}

vector<string> splitLine(const string& line) {
    vector<string> fields;
    stringstream ss(line);
    string field;

    while (getline(ss, field, '|')) {
        fields.push_back(trim(field));
    }

    return fields;
}

class SecurityLogger {
private:
    string filename = "security_logs.txt";
    int nextEventID = 1;

public:
    SecurityLogger() {
        ifstream file(filename);
        string line;
        int largestID = 0;

        while (getline(file, line)) {
            vector<string> fields = splitLine(line);

            if (!fields.empty()) {
                try {
                    largestID = max(largestID, stoi(fields[0]));
                } catch (...) {
                }
            }
        }

        nextEventID = largestID + 1;
    }

    void logEvent(
        const string& username,
        const string& role,
        const string& action,
        const string& result
    ) {
        ofstream file(filename, ios::app);

        if (!file.is_open()) {
            cout << "Warning: Could not write security log.\n";
            return;
        }

        time_t now = time(nullptr);
        tm* localTime = localtime(&now);
        string timestamp = "Unknown";

        if (localTime != nullptr) {
            stringstream ss;
            ss << put_time(localTime, "%Y-%m-%d %H:%M:%S");
            timestamp = ss.str();
        }

        file << nextEventID << " | "
             << timestamp << " | "
             << cleanField(username) << " | "
             << cleanField(role) << " | "
             << cleanField(action) << " | "
             << cleanField(result) << '\n';

        if (file.good()) {
            cout << "[Security Event #" << nextEventID
                 << " recorded]\n";
            nextEventID++;
        }
    }

    vector<vector<string>> readLogs() const {
        vector<vector<string>> records;
        ifstream file(filename);
        string line;

        while (getline(file, line)) {
            vector<string> fields = splitLine(line);

            if (fields.size() >= 6) {
                records.push_back(fields);
            }
        }

        return records;
    }

    int countPreviousDeniedRequests(const string& username) const {
        int count = 0;

        for (const auto& fields : readLogs()) {
            if (fields[2] == username &&
                fields[4].find("RESOURCE_ACCESS") == 0 &&
                fields[5].find("DENIED") == 0) {
                count++;
            }
        }

        return count;
    }

    void viewLogs() const {
        auto records = readLogs();

        cout << "\n========== SECURITY LOGS ==========\n";

        if (records.empty()) {
            cout << "No security events found.\n";
            return;
        }

        for (const auto& fields : records) {
            for (size_t i = 0; i < fields.size(); i++) {
                if (i > 0) cout << " | ";
                cout << fields[i];
            }
            cout << '\n';
        }

        cout << "===================================\n";
    }

    void viewStatistics() const {
        int total = 0, loginAttempts = 0, successful = 0, failed = 0;
        int accessRequests = 0, granted = 0, denied = 0;
        int usersCreated = 0, usersDeleted = 0;
        int resourcesCreated = 0, resourcesDeleted = 0;
        int riskAssessments = 0, highRisk = 0, logouts = 0;

        for (const auto& fields : readLogs()) {
            total++;

            string action = fields[4];
            string result = fields[5];

            if (action == "LOGIN") {
                loginAttempts++;
                if (result == "SUCCESS") successful++;
                else if (result.find("FAILED") == 0) failed++;
            }

            if (action.find("RESOURCE_ACCESS") == 0) {
                accessRequests++;
                if (result == "GRANTED") granted++;
                else if (result.find("DENIED") == 0) denied++;
            }

            if (action == "USER_CREATED") usersCreated++;
            if (action == "USER_DELETED") usersDeleted++;
            if (action == "RESOURCE_CREATED") resourcesCreated++;
            if (action == "RESOURCE_DELETED") resourcesDeleted++;
            if (action == "LOGOUT") logouts++;

            if (action.find("RISK_ASSESSMENT") == 0) {
                riskAssessments++;
                if (result.find("_HIGH") != string::npos) highRisk++;
            }
        }

        cout << "\n====== VIGILX SECURITY STATISTICS ======\n";
        cout << "Total Events          : " << total << '\n';
        cout << "Login Attempts        : " << loginAttempts << '\n';
        cout << "Successful Logins     : " << successful << '\n';
        cout << "Failed Logins         : " << failed << '\n';
        cout << "Access Requests       : " << accessRequests << '\n';
        cout << "Access Granted        : " << granted << '\n';
        cout << "Access Denied         : " << denied << '\n';
        cout << "Users Created         : " << usersCreated << '\n';
        cout << "Users Deleted         : " << usersDeleted << '\n';
        cout << "Resources Created     : " << resourcesCreated << '\n';
        cout << "Resources Deleted     : " << resourcesDeleted << '\n';
        cout << "Risk Assessments      : " << riskAssessments << '\n';
        cout << "High-Risk Assessments : " << highRisk << '\n';
        cout << "Logout Events         : " << logouts << '\n';
        cout << "========================================\n";
    }

    void viewThreatAlerts() const {
        auto records = readLogs();
        map<string, int> failedLogins;
        map<string, int> deniedRequests;
        int alertCount = 0;

        for (const auto& fields : records) {
            string username = fields[2];
            string action = fields[4];
            string result = fields[5];

            if (action == "LOGIN" && result.find("FAILED") == 0) {
                failedLogins[username]++;
            }

            if (action.find("RESOURCE_ACCESS") == 0 &&
                result.find("DENIED") == 0) {
                deniedRequests[username]++;
            }
        }

        cout << "\n========== VIGILX THREAT ALERTS ==========\n";

        for (const auto& entry : failedLogins) {
            if (entry.second >= 3) {
                cout << "[HIGH] Repeated failed logins\n";
                cout << "Username: " << entry.first << '\n';
                cout << "Attempts: " << entry.second << "\n\n";
                alertCount++;
            }
        }

        for (const auto& entry : deniedRequests) {
            if (entry.second >= 3) {
                cout << "[MEDIUM] Repeated access denials\n";
                cout << "Username: " << entry.first << '\n';
                cout << "Denied requests: " << entry.second << "\n\n";
                alertCount++;
            }
        }

        for (const auto& fields : records) {
            if (fields[4].find("RISK_ASSESSMENT") == 0 &&
                fields[5].find("_HIGH") != string::npos) {
                cout << "[HIGH] High-risk access activity\n";
                cout << "Event ID: " << fields[0] << '\n';
                cout << "Username: " << fields[2] << '\n';
                cout << "Result: " << fields[5] << "\n\n";
                alertCount++;
            }
        }

        if (alertCount == 0) {
            cout << "No alerts matched the configured rules.\n";
        }

        cout << "Total matching alerts: " << alertCount << '\n';
        cout << "==========================================\n";
    }
};

class User {
private:
    int userID;
    string username;
    bool active;

public:
    User(int id, const string& name)
        : userID(id), username(name), active(true) {}

    virtual ~User() = default;

    int getUserID() const { return userID; }
    string getUsername() const { return username; }
    bool isActive() const { return active; }
    void deactivate() { active = false; }

    virtual string getRole() const = 0;
    virtual void displayPermissions() const = 0;

    void display() const {
        cout << "\nUser ID  : " << userID
             << "\nUsername : " << username
             << "\nRole     : " << getRole()
             << "\nStatus   : " << (active ? "Active" : "Inactive")
             << '\n';
    }
};

class Admin : public User {
public:
    Admin(int id, const string& name) : User(id, name) {}
    string getRole() const override { return "Admin"; }

    void displayPermissions() const override {
        cout << "Admin permissions: All resource classifications.\n";
    }
};

class Employee : public User {
public:
    Employee(int id, const string& name) : User(id, name) {}
    string getRole() const override { return "Employee"; }

    void displayPermissions() const override {
        cout << "Employee permissions: Public and Internal resources.\n";
    }
};

class Guest : public User {
public:
    Guest(int id, const string& name) : User(id, name) {}
    string getRole() const override { return "Guest"; }

    void displayPermissions() const override {
        cout << "Guest permissions: Public resources only.\n";
    }
};

class UserManager {
private:
    vector<unique_ptr<User>> users;
    int nextUserID = 1;
    SecurityLogger& logger;
    const string filename = "users.txt";

    void saveUsers() const {
        ofstream file(filename);

        if (!file.is_open()) {
            cout << "Warning: Could not save users.txt.\n";
            return;
        }

        for (const auto& user : users) {
            file << user->getUserID() << " | "
                 << user->getRole() << " | "
                 << cleanField(user->getUsername()) << '\n';
        }
    }

    void loadUsers() {
        ifstream file(filename);
        string line;
        int largestID = 0;

        while (getline(file, line)) {
            vector<string> fields = splitLine(line);

            if (fields.size() < 3) continue;

            try {
                int id = stoi(fields[0]);
                string role = fields[1];
                string username = fields[2];

                if (role == "Admin") {
                    users.push_back(make_unique<Admin>(id, username));
                } else if (role == "Employee") {
                    users.push_back(make_unique<Employee>(id, username));
                } else if (role == "Guest") {
                    users.push_back(make_unique<Guest>(id, username));
                } else {
                    continue;
                }

                largestID = max(largestID, id);
            } catch (...) {
                cout << "Warning: Skipping invalid user record.\n";
            }
        }

        nextUserID = largestID + 1;
    }

public:
    explicit UserManager(SecurityLogger& securityLogger)
        : logger(securityLogger) {
        loadUsers();
    }

    User* findUserByID(int id) const {
        for (const auto& user : users) {
            if (user->getUserID() == id) return user.get();
        }
        return nullptr;
    }

    void addUser() {
        string username;
        int choice;

        cout << "Enter username: ";
        getline(cin, username);
        username = trim(username);

        if (username.empty()) {
            cout << "Username cannot be empty.\n";
            return;
        }

        cout << "1. Admin\n2. Employee\n3. Guest\nSelect role: ";

        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input.\n";
            return;
        }

        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        if (choice < 1 || choice > 3) {
            cout << "Invalid role.\n";
            return;
        }

        int id = nextUserID++;

        if (choice == 1) users.push_back(make_unique<Admin>(id, username));
        else if (choice == 2) users.push_back(make_unique<Employee>(id, username));
        else users.push_back(make_unique<Guest>(id, username));

        User* user = users.back().get();

        saveUsers();

        cout << "User created and saved successfully.\n";
        user->display();

        logger.logEvent(
            username, user->getRole(), "USER_CREATED", "SUCCESS"
        );
    }

    void viewUsers() const {
        if (users.empty()) {
            cout << "No users found.\n";
            return;
        }

        for (const auto& user : users) user->display();
    }

    void searchUser() const {
        int id;
        cout << "Enter User ID: ";

        if (!(cin >> id)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input.\n";
            return;
        }

        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        User* user = findUserByID(id);

        if (!user) {
            cout << "User not found.\n";
            return;
        }

        user->display();
        user->displayPermissions();
    }

    void deleteUser() {
        int id;
        cout << "Enter User ID to delete: ";

        if (!(cin >> id)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input.\n";
            return;
        }

        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        for (auto it = users.begin(); it != users.end(); ++it) {
            if ((*it)->getUserID() == id) {
                string name = (*it)->getUsername();
                string role = (*it)->getRole();

                users.erase(it);
                saveUsers();

                logger.logEvent(name, role, "USER_DELETED", "SUCCESS");
                cout << "User deleted and changes saved.\n";
                return;
            }
        }

        cout << "User not found.\n";
    }
};

class Resource {
private:
    int resourceID;
    string resourceName;
    string classification;

public:
    Resource(int id, const string& name, const string& level)
        : resourceID(id), resourceName(name), classification(level) {}

    int getResourceID() const { return resourceID; }
    string getResourceName() const { return resourceName; }
    string getClassification() const { return classification; }

    void display() const {
        cout << "\nResource ID    : " << resourceID
             << "\nResource Name  : " << resourceName
             << "\nClassification : " << classification << '\n';
    }
};

class RiskScoringEngine {
public:
    int calculateRiskScore(
        const User& user,
        const Resource& resource,
        int previousDenials
    ) const {
        int score = 0;
        string role = user.getRole();
        string level = resource.getClassification();

        if ((role == "Employee" && level == "Confidential") ||
            (role == "Guest" && level != "Public")) {
            score += 40;
        }

        score += min(previousDenials * 15, 60);
        return min(score, 100);
    }

    string getRiskLevel(int score) const {
        if (score < 30) return "LOW";
        if (score < 60) return "MEDIUM";
        return "HIGH";
    }

    void displayRiskAssessment(int score) const {
        cout << "\n========== RISK ASSESSMENT ==========\n";
        cout << "Risk Score : " << score << "/100\n";
        cout << "Risk Level : " << getRiskLevel(score) << '\n';
        cout << "=====================================\n";
    }
};

class ResourceManager {
private:
    vector<Resource> resources;
    int nextResourceID = 1;
    SecurityLogger& logger;
    RiskScoringEngine riskEngine;
    const string filename = "resources.txt";

    void saveResources() const {
        ofstream file(filename);

        if (!file.is_open()) {
            cout << "Warning: Could not save resources.txt.\n";
            return;
        }

        for (const auto& resource : resources) {
            file << resource.getResourceID() << " | "
                 << resource.getClassification() << " | "
                 << cleanField(resource.getResourceName()) << '\n';
        }
    }

    void loadResources() {
        ifstream file(filename);
        string line;
        int largestID = 0;

        while (getline(file, line)) {
            vector<string> fields = splitLine(line);

            if (fields.size() < 3) continue;

            try {
                int id = stoi(fields[0]);
                string level = fields[1];
                string name = fields[2];

                if (level != "Public" &&
                    level != "Internal" &&
                    level != "Confidential") {
                    continue;
                }

                resources.emplace_back(id, name, level);
                largestID = max(largestID, id);
            } catch (...) {
                cout << "Warning: Skipping invalid resource record.\n";
            }
        }

        nextResourceID = largestID + 1;
    }

public:
    explicit ResourceManager(SecurityLogger& securityLogger)
        : logger(securityLogger) {
        loadResources();
    }

    const Resource* findResourceByID(int id) const {
        for (const auto& resource : resources) {
            if (resource.getResourceID() == id) return &resource;
        }
        return nullptr;
    }

    void addResource() {
        string name;
        int choice;

        cout << "Enter resource name: ";
        getline(cin, name);
        name = trim(name);

        if (name.empty()) {
            cout << "Resource name cannot be empty.\n";
            return;
        }

        cout << "1. Public\n2. Internal\n3. Confidential\nSelect: ";

        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input.\n";
            return;
        }

        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        if (choice < 1 || choice > 3) {
            cout << "Invalid classification.\n";
            return;
        }

        string level = choice == 1 ? "Public"
                     : choice == 2 ? "Internal"
                     : "Confidential";

        int id = nextResourceID++;
        resources.emplace_back(id, name, level);

        saveResources();

        cout << "Resource created and saved successfully.\n";
        resources.back().display();

        logger.logEvent(
            "SYSTEM", "System", "RESOURCE_CREATED", "SUCCESS"
        );
    }

    void viewResources() const {
        if (resources.empty()) {
            cout << "No resources found.\n";
            return;
        }

        for (const auto& resource : resources) resource.display();
    }

    void searchResource() const {
        int id;
        cout << "Enter Resource ID: ";

        if (!(cin >> id)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input.\n";
            return;
        }

        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        const Resource* resource = findResourceByID(id);

        if (!resource) {
            cout << "Resource not found.\n";
            return;
        }

        resource->display();
    }

    void deleteResource() {
        int id;
        cout << "Enter Resource ID to delete: ";

        if (!(cin >> id)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input.\n";
            return;
        }

        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        for (auto it = resources.begin(); it != resources.end(); ++it) {
            if (it->getResourceID() == id) {
                resources.erase(it);
                saveResources();

                logger.logEvent(
                    "SYSTEM", "System", "RESOURCE_DELETED", "SUCCESS"
                );

                cout << "Resource deleted and changes saved.\n";
                return;
            }
        }

        cout << "Resource not found.\n";
    }

    void requestAccess(const User& user) const {
        viewResources();

        int id;
        cout << "Enter Resource ID for access: ";

        if (!(cin >> id)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');

            logger.logEvent(
                user.getUsername(), user.getRole(),
                "RESOURCE_ACCESS:INVALID_INPUT", "DENIED_INVALID_INPUT"
            );

            cout << "Invalid input.\n";
            return;
        }

        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        const Resource* resource = findResourceByID(id);

        if (!resource) {
            cout << "Resource not found. Access denied.\n";

            logger.logEvent(
                user.getUsername(), user.getRole(),
                "RESOURCE_ACCESS:ID_" + to_string(id),
                "DENIED_NOT_FOUND"
            );
            return;
        }

        int previousDenials =
            logger.countPreviousDeniedRequests(user.getUsername());

        int score = riskEngine.calculateRiskScore(
            user, *resource, previousDenials
        );

        string riskLevel = riskEngine.getRiskLevel(score);
        riskEngine.displayRiskAssessment(score);

        logger.logEvent(
            user.getUsername(),
            user.getRole(),
            "RISK_ASSESSMENT:" + resource->getResourceName(),
            "SCORE_" + to_string(score) + "_" + riskLevel
        );

        string role = user.getRole();
        string level = resource->getClassification();

        bool allowed =
            role == "Admin" ||
            (role == "Employee" &&
             (level == "Public" || level == "Internal")) ||
            (role == "Guest" && level == "Public");

        if (allowed) {
            cout << "\nACCESS GRANTED\n";
            resource->display();

            logger.logEvent(
                user.getUsername(), role,
                "RESOURCE_ACCESS:" + resource->getResourceName(),
                "GRANTED"
            );
        } else {
            cout << "\nACCESS DENIED\n";
            cout << "Your role cannot access this resource.\n";

            logger.logEvent(
                user.getUsername(), role,
                "RESOURCE_ACCESS:" + resource->getResourceName(),
                "DENIED"
            );
        }
    }
};

class VigilX {
private:
    SecurityLogger logger;
    UserManager userManager;
    ResourceManager resourceManager;
    int currentUserID = -1;

    User* getCurrentUser() const {
        if (currentUserID == -1) return nullptr;

        User* user = userManager.findUserByID(currentUserID);

        if (!user || !user->isActive()) return nullptr;
        return user;
    }

    void login() {
        if (getCurrentUser()) {
            cout << "A user is already logged in. Log out first.\n";
            return;
        }

        int id;
        string username;

        cout << "Enter User ID: ";

        if (!(cin >> id)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            cout << "Invalid input.\n";
            return;
        }

        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        cout << "Enter username: ";
        getline(cin, username);

        User* user = userManager.findUserByID(id);

        if (!user || user->getUsername() != username) {
            cout << "Login failed.\n";
            logger.logEvent(username, "Unknown", "LOGIN", "FAILED");
            return;
        }

        if (!user->isActive()) {
            cout << "Login failed: inactive user.\n";

            logger.logEvent(
                username, user->getRole(), "LOGIN", "FAILED_INACTIVE"
            );
            return;
        }

        currentUserID = id;
        cout << "Login successful. Welcome, " << username << "!\n";

        logger.logEvent(
            username, user->getRole(), "LOGIN", "SUCCESS"
        );
    }

    void logout() {
        User* user = getCurrentUser();

        if (!user) {
            currentUserID = -1;
            cout << "No active user session.\n";
            return;
        }

        logger.logEvent(
            user->getUsername(), user->getRole(), "LOGOUT", "SUCCESS"
        );

        cout << "Logged out successfully.\n";
        currentUserID = -1;
    }

    void viewSession() const {
        User* user = getCurrentUser();

        if (!user) {
            cout << "No active session.\n";
            return;
        }

        user->display();
        user->displayPermissions();
    }

    void accessControl() {
        User* user = getCurrentUser();

        if (!user) {
            cout << "Please log in before requesting access.\n";

            logger.logEvent(
                "Unauthenticated", "Unknown",
                "RESOURCE_ACCESS", "DENIED_NOT_AUTHENTICATED"
            );
            return;
        }

        resourceManager.requestAccess(*user);
    }

public:
    VigilX()
        : logger(), userManager(logger), resourceManager(logger) {}

    void run() {
        int choice;

        do {
            cout << "\n========== VIGILX SECURITY ENGINE ==========\n";
            cout << "1. Add User\n";
            cout << "2. View Users\n";
            cout << "3. Search User\n";
            cout << "4. Delete User\n";
            cout << "5. Add Resource\n";
            cout << "6. View Resources\n";
            cout << "7. Search/Delete Resource\n";
            cout << "8. Security Logs\n";
            cout << "9. Security Statistics\n";
            cout << "10. Login\n";
            cout << "11. Logout\n";
            cout << "12. View Current Session\n";
            cout << "13. Request Resource Access\n";
            cout << "14. Threat Alerts\n";
            cout << "0. Exit\n";
            cout << "============================================\n";
            cout << "Enter choice: ";

            if (!(cin >> choice)) {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "Invalid input.\n";
                continue;
            }

            cin.ignore(numeric_limits<streamsize>::max(), '\n');

            switch (choice) {
                case 1: userManager.addUser(); break;
                case 2: userManager.viewUsers(); break;
                case 3: userManager.searchUser(); break;
                case 4: userManager.deleteUser(); break;
                case 5: resourceManager.addResource(); break;
                case 6: resourceManager.viewResources(); break;

                case 7: {
                    int subChoice;
                    cout << "1. Search Resource\n2. Delete Resource\nChoice: ";

                    if (!(cin >> subChoice)) {
                        cin.clear();
                        cin.ignore(numeric_limits<streamsize>::max(), '\n');
                        cout << "Invalid input.\n";
                        break;
                    }

                    cin.ignore(numeric_limits<streamsize>::max(), '\n');

                    if (subChoice == 1) resourceManager.searchResource();
                    else if (subChoice == 2) resourceManager.deleteResource();
                    else cout << "Invalid choice.\n";

                    break;
                }

                case 8: logger.viewLogs(); break;
                case 9: logger.viewStatistics(); break;
                case 10: login(); break;
                case 11: logout(); break;
                case 12: viewSession(); break;
                case 13: accessControl(); break;
                case 14: logger.viewThreatAlerts(); break;

                case 0:
                    if (getCurrentUser()) logout();
                    cout << "Exiting VigilX. Goodbye!\n";
                    break;

                default:
                    cout << "Invalid choice.\n";
            }

        } while (choice != 0);
    }
};

int main() {
    VigilX system;
    system.run();
    return 0;
}
