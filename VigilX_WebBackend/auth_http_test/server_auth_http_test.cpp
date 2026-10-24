
#include "httplib.h"

#include "auth_foundation.h"
#include "auth_validation.h"
#include "auth_storage.h"
#include "auth_session.h"

#include <nlohmann/json.hpp>


#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>
#include <chrono>

using namespace std;

const string DATA_PATH = "./test_data/";
mutex logMutex;

// Shared authentication state: one instance for the entire server.
VigilXAuth::CredentialStore credentialStore("./test_data/credentials.txt");
VigilXAuth::SessionManager sessionManager;

// Serializes signup checks across users.txt and credentials.txt.
mutex signupMutex;

// Limits repeated failed login attempts for each username.
struct LoginAttemptState {
    int failedAttempts = 0;
    chrono::steady_clock::time_point lockedUntil{};
};

mutex loginAttemptMutex;
map<string, LoginAttemptState> loginAttempts;

bool isLoginLocked(const string& username) {
    lock_guard<mutex> lock(loginAttemptMutex);

    auto it = loginAttempts.find(username);
    if (it == loginAttempts.end()) {
        return false;
    }

    const auto now = chrono::steady_clock::now();
    const auto noLock = chrono::steady_clock::time_point{};

    if (it->second.lockedUntil == noLock) {
        return false;
    }

    if (now >= it->second.lockedUntil) {
        it->second.failedAttempts = 0;
        it->second.lockedUntil = noLock;
        return false;
    }

    return true;
}

void recordFailedLogin(const string& username) {
    lock_guard<mutex> lock(loginAttemptMutex);

    auto& state = loginAttempts[username];

    if (chrono::steady_clock::now() < state.lockedUntil) {
        return;
    }

    ++state.failedAttempts;

    if (state.failedAttempts >= 5) {
        state.lockedUntil =
            chrono::steady_clock::now() + chrono::minutes(15);
    }
}

void resetLoginAttempts(const string& username) {
    lock_guard<mutex> lock(loginAttemptMutex);
    loginAttempts.erase(username);
}


string trim(const string& value) {
    size_t first = value.find_first_not_of(" \t\r\n");

    if (first == string::npos) {
        return "";
    }

    size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

string jsonEscape(const string& value) {
    string result;

    for (unsigned char c : value) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (c < 0x20) {
                    result += ' ';
                } else {
                    result += static_cast<char>(c);
                }
        }
    }

    return result;
}

vector<string> splitLine(const string& line) {
    vector<string> fields;
    size_t start = 0;

    while (true) {
        size_t position = line.find('|', start);

        if (position == string::npos) {
            fields.push_back(trim(line.substr(start)));
            break;
        }

        fields.push_back(trim(line.substr(start, position - start)));
        start = position + 1;
    }

    return fields;
}

vector<vector<string>> readRecords(
    const string& filename,
    size_t minimumFields
) {
    vector<vector<string>> records;
    ifstream file(DATA_PATH + filename);
    string line;

    if (!file.is_open()) {
        return records;
    }

    while (getline(file, line)) {
        vector<string> fields = splitLine(line);

        if (fields.size() >= minimumFields) {
            records.push_back(fields);
        }
    }

    return records;
}

bool appendRegisteredUser(const string& role, const string& username) {
    auto records = readRecords("users.txt", 3);
    int maximumID = 0;

    for (const auto& fields : records) {
        try {
            maximumID = max(maximumID, stoi(fields[0]));
        } catch (...) {
            // Ignore malformed IDs when finding the next available ID.
        }

        if (fields.size() >= 3 && trim(fields[2]) == username) {
            return false;
        }
    }

    ofstream file(DATA_PATH + "users.txt", ios::app);
    if (!file.is_open()) {
        return false;
    }

    file << maximumID + 1 << " | " << role << " | " << username << '\n';
    file.flush();
    return file.good();
}

string safeJson(const string& value) {
    return "\"" + jsonEscape(value) + "\"";
}

void sendJson(httplib::Response& response, const string& body) {
    response.set_header("Cache-Control", "no-store");
    response.set_content(body, "application/json; charset=utf-8");
}

bool validRole(const string& role) {
    return role == "Admin" ||
           role == "Employee" ||
           role == "Guest";
}

bool validClassification(const string& classification) {
    return classification == "Public" ||
           classification == "Internal" ||
           classification == "Confidential";
}

bool isFailedLogin(const vector<string>& fields) {
    return fields.size() >= 6 &&
           fields[4] == "LOGIN" &&
           fields[5] == "FAILED";
}

bool isDeniedAccess(const vector<string>& fields) {
    return fields.size() >= 6 &&
           fields[4].find("RESOURCE_ACCESS") == 0 &&
           fields[5] == "DENIED";
}

bool isHighRiskAssessment(const vector<string>& fields) {
    return fields.size() >= 6 &&
           fields[4].find("RISK_ASSESSMENT") == 0 &&
           fields[5].find("HIGH") != string::npos;
}

string alertJson(
    const string& severity,
    const string& type,
    const string& message,
    int count
) {
    return "{\"severity\":" + safeJson(severity) +
           ",\"type\":" + safeJson(type) +
           ",\"message\":" + safeJson(message) +
           ",\"count\":" + to_string(count) + "}";
}

string currentTimestamp() {
    time_t now = time(nullptr);
    tm localTime{};

#ifdef _WIN32
    localtime_s(&localTime, &now);
#else
    localtime_r(&now, &localTime);
#endif

    ostringstream output;
    output << put_time(&localTime, "%Y-%m-%d %H:%M:%S");
    return output.str();
}

int nextEventID() {
    auto records = readRecords("security_logs.txt", 6);
    int maximumID = 0;

    for (const auto& fields : records) {
        try {
            maximumID = max(maximumID, stoi(fields[0]));
        } catch (...) {
            // Ignore records with a non-numeric event ID.
        }
    }

    return maximumID + 1;
}

bool appendLog(
    const string& username,
    const string& role,
    const string& action,
    const string& result
) {
    lock_guard<mutex> lock(logMutex);

    ofstream file(DATA_PATH + "security_logs.txt", ios::app);

    if (!file.is_open()) {
        return false;
    }

    int eventID = nextEventID();

    file << eventID << " | "
         << currentTimestamp() << " | "
         << username << " | "
         << role << " | "
         << action << " | "
         << result << '\n';

    file.flush();
    return file.good();
}

int countPreviousDeniedRequests(const string& username) {
    auto logs = readRecords("security_logs.txt", 6);
    int count = 0;

    for (const auto& fields : logs) {
        if (fields[2] == username &&
            fields[4].find("RESOURCE_ACCESS") == 0 &&
            fields[5] == "DENIED") {
            count++;
        }
    }

    return count;
}

int calculateRiskScore(
    const string& role,
    const string& classification,
    int previousDenials
) {
    int score = 0;

    if ((role == "Employee" && classification == "Confidential") ||
        (role == "Guest" && classification != "Public")) {
        score += 40;
    }

    score += min(previousDenials * 15, 60);

    return min(score, 100);
}

string getRiskLevel(int score) {
    if (score < 30) {
        return "LOW";
    }

    if (score < 60) {
        return "MEDIUM";
    }

    return "HIGH";
}

bool hasAccessPermission(
    const string& role,
    const string& classification
) {
    return role == "Admin" ||
           (role == "Employee" &&
            (classification == "Public" ||
             classification == "Internal")) ||
           (role == "Guest" && classification == "Public");
}

// Extract the VigilX session token from the browser Cookie header.
string getSessionToken(const httplib::Request& request) {
    const string cookieHeader = request.get_header_value("Cookie");
    istringstream cookies(cookieHeader);
    string cookie;

    while (getline(cookies, cookie, ';')) {
        cookie = trim(cookie);

        const size_t equals = cookie.find('=');
        if (equals == string::npos) {
            continue;
        }

        const string name = trim(cookie.substr(0, equals));
        const string value = trim(cookie.substr(equals + 1));

        if (name == "vigilx_session") {
            return value;
        }
    }

    return "";
}

// Resolve the authenticated identity using the server-side session store.
bool getAuthenticatedSession(
    const httplib::Request& request,
    VigilXAuth::Session& session
) {
    const string token = getSessionToken(request);

    if (token.empty()) {
        return false;
    }

    return sessionManager.get(token, session);
}

void setSessionCookie(
    httplib::Response& response,
    const string& token
) {
    response.set_header(
        "Set-Cookie",
        "vigilx_session=" + token +
        "; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600"
    );
}

void clearSessionCookie(httplib::Response& response) {
    response.set_header(
        "Set-Cookie",
        "vigilx_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
    );
}


// Require a valid server-side session before serving protected APIs.
bool requireAuthenticatedSession(
    const httplib::Request& request,
    httplib::Response& response,
    VigilXAuth::Session& session
) {
    response.set_header("Cache-Control", "no-store");

    if (getAuthenticatedSession(request, session)) {
        return true;
    }

    response.status = 401;
    sendJson(response, R"({"error":"Authentication required."})");
    return false;
}

int main() {
    httplib::Server server;

    if (!server.set_mount_point("/", "./public")) {
        cerr << "Could not mount the public folder.\n";
        return 1;
    }


    // Authentication: public signup is restricted to Employee and Guest.
    server.Post("/api/auth/signup", [](const httplib::Request& request,
                                       httplib::Response& response) {
        response.set_header("Cache-Control", "no-store");

        nlohmann::json body = nlohmann::json::object();

        try {
            body = nlohmann::json::parse(request.body);
        } catch (...) {
            response.status = 400;
            sendJson(response, R"({"error":"Invalid JSON request."})");
            return;
        }

        string username, password, role;

        if (!VigilXAuth::validSignupRequest(
                body, username, password, role)) {
            response.status = 400;
            sendJson(
                response,
                R"({"error":"Invalid signup details. Use a valid username, an 8-128 character password, and role Employee or Guest."})"
            );
            return;
        }

        lock_guard<mutex> signupLock(signupMutex);

        // Never let public signup claim an existing dashboard account.
        auto existingUsers = readRecords("users.txt", 3);

        for (const auto& fields : existingUsers) {
            if (fields.size() >= 3 &&
                trim(fields[2]) == username) {
                response.status = 409;
                sendJson(
                    response,
                    R"({"error":"This username is already reserved. Contact the administrator."})"
                );
                return;
            }
        }

        map<string, VigilXAuth::Credential> credentials;

        if (!credentialStore.load(credentials)) {
            response.status = 500;
            sendJson(
                response,
                R"({"error":"Credential storage is unavailable."})"
            );
            return;
        }

        if (credentials.find(username) != credentials.end()) {
            response.status = 409;
            sendJson(response, R"({"error":"Username is already registered."})");
            return;
        }

        string salt, passwordHash;

        if (!VigilXAuth::generateRandomHex(16, salt) ||
            !VigilXAuth::hashPassword(password, salt, passwordHash)) {
            response.status = 500;
            sendJson(response, R"({"error":"Could not secure the password."})");
            return;
        }

        VigilXAuth::Credential credential{
            username, role, salt, passwordHash
        };

        if (!credentialStore.createIfAbsent(credential)) {
            response.status = 409;
            sendJson(
                response,
                R"({"error":"Account could not be created. Check credential storage or username availability."})"
            );
            return;
        }

        if (!appendRegisteredUser(role, username)) {
            response.status = 500;
            sendJson(
                response,
                R"({"error":"Credentials were created, but the dashboard user record could not be saved. Contact the administrator."})"
            );
            return;
        }

        // Do not log passwords, salts, or password hashes.
        if (!appendLog(username, role, "SIGNUP", "SUCCESS")) {
            response.status = 500;
            sendJson(
                response,
                R"({"error":"Account was created, but the security log could not be written. Contact the administrator."})"
            );
            return;
        }

        response.status = 201;
        sendJson(
            response,
            R"({"success":true,"message":"Account created. Please log in."})"
        );
    });

    server.Post("/api/auth/login", [](const httplib::Request& request,
                                      httplib::Response& response) {
        response.set_header("Cache-Control", "no-store");

        nlohmann::json body = nlohmann::json::object();

        try {
            body = nlohmann::json::parse(request.body);
        } catch (...) {
            response.status = 400;
            sendJson(response, R"({"error":"Invalid JSON request."})");
            return;
        }

        string username, password;

        if (!VigilXAuth::validLoginRequest(body, username, password)) {
            response.status = 400;
            sendJson(response, R"({"error":"Enter a valid username and password."})");
            return;
        }

        map<string, VigilXAuth::Credential> credentials;

        if (!credentialStore.load(credentials)) {
            response.status = 500;
            sendJson(response, R"({"error":"Credential storage is unavailable."})");
            return;
        }

        auto it = credentials.find(username);

        // Apply the same lockout behavior before checking credentials.
        if (isLoginLocked(username)) {
            response.status = 429;
            response.set_header("Retry-After", "900");
            sendJson(
                response,
                R"({"error":"Too many failed login attempts. Try again in 15 minutes."})"
            );
            return;
        }

        // Same error for unknown usernames and incorrect passwords.
        if (it == credentials.end() ||
            !VigilXAuth::verifyPassword(
                password, it->second.salt, it->second.passwordHash)) {
            recordFailedLogin(username);
            appendLog(username, "Unknown", "LOGIN", "FAILED");
            response.status = 401;
            sendJson(response, R"({"error":"Invalid username or password."})");
            return;
        }

        resetLoginAttempts(username);

        string token;

        if (!sessionManager.create(username, it->second.role, token)) {
            response.status = 500;
            sendJson(response, R"({"error":"Could not create a session."})");
            return;
        }

        if (!appendLog(username, it->second.role, "LOGIN", "SUCCESS")) {
            sessionManager.remove(token);
            response.status = 500;
            sendJson(response, R"({"error":"Could not write the security log."})");
            return;
        }

        setSessionCookie(response, token);

        sendJson(
            response,
            nlohmann::json{
                {"success", true},
                {"username", username},
                {"role", it->second.role}
            }.dump()
        );
    });

    server.Get("/api/auth/me", [](const httplib::Request& request,
                                  httplib::Response& response) {
        response.set_header("Cache-Control", "no-store");

        VigilXAuth::Session session;

        if (!getAuthenticatedSession(request, session)) {
            response.status = 401;
            sendJson(response, R"({"error":"Not authenticated."})");
            return;
        }

        sendJson(
            response,
            nlohmann::json{
                {"authenticated", true},
                {"username", session.username},
                {"role", session.role}
            }.dump()
        );
    });

    server.Post("/api/auth/logout", [](const httplib::Request& request,
                                       httplib::Response& response) {
        response.set_header("Cache-Control", "no-store");

        const string token = getSessionToken(request);

        if (!token.empty()) {
            VigilXAuth::Session session;

            if (sessionManager.get(token, session)) {
                appendLog(
                    session.username, session.role, "LOGOUT", "SUCCESS"
                );
            }

            sessionManager.remove(token);
        }

        clearSessionCookie(response);
        sendJson(response, R"({"success":true,"message":"Logged out."})");
    });

    server.Get("/api/health", [](const httplib::Request&,
                                 httplib::Response& response) {
        sendJson(
            response,
            R"({"status":"ok","service":"VigilX","language":"C++"})"
        );
    });

    server.Get("/api/users", [](const httplib::Request& request,
                                httplib::Response& response) {
        VigilXAuth::Session session;
        if (!requireAuthenticatedSession(request, response, session)) {
            return;
        }

        auto records = readRecords("users.txt", 3);

        string json = "{\"users\":[";
        bool first = true;

        for (const auto& fields : records) {
            if (!validRole(fields[1])) {
                continue;
            }

            if (!first) json += ",";
            first = false;

            json += "{\"id\":" + safeJson(fields[0]) +
                    ",\"role\":" + safeJson(fields[1]) +
                    ",\"username\":" + safeJson(fields[2]) + "}";
        }

        json += "]}";
        sendJson(response, json);
    });

    server.Get("/api/resources", [](const httplib::Request& request,
                                    httplib::Response& response) {
        VigilXAuth::Session session;
        if (!requireAuthenticatedSession(request, response, session)) {
            return;
        }

        auto records = readRecords("resources.txt", 3);

        string json = "{\"resources\":[";
        bool first = true;

        for (const auto& fields : records) {
            if (!validClassification(fields[1])) {
                continue;
            }

            if (!first) json += ",";
            first = false;

            json += "{\"id\":" + safeJson(fields[0]) +
                    ",\"classification\":" + safeJson(fields[1]) +
                    ",\"name\":" + safeJson(fields[2]) + "}";
        }

        json += "]}";
        sendJson(response, json);
    });

    server.Get("/api/logs", [](const httplib::Request& request,
                               httplib::Response& response) {
        VigilXAuth::Session session;
        if (!requireAuthenticatedSession(request, response, session)) {
            return;
        }

        auto records = readRecords("security_logs.txt", 6);

        string json = "{\"logs\":[";
        bool first = true;

        int start = static_cast<int>(records.size()) - 1;
        int end = max(-1, start - 20);

        for (int i = start; i > end; --i) {
            const auto& fields = records[i];

            if (!first) json += ",";
            first = false;

            json += "{\"id\":" + safeJson(fields[0]) +
                    ",\"timestamp\":" + safeJson(fields[1]) +
                    ",\"username\":" + safeJson(fields[2]) +
                    ",\"role\":" + safeJson(fields[3]) +
                    ",\"action\":" + safeJson(fields[4]) +
                    ",\"result\":" + safeJson(fields[5]) + "}";
        }

        json += "]}";
        sendJson(response, json);
    });

    server.Get("/api/stats", [](const httplib::Request& request,
                                httplib::Response& response) {
        VigilXAuth::Session session;
        if (!requireAuthenticatedSession(request, response, session)) {
            return;
        }

        auto users = readRecords("users.txt", 3);
        auto resources = readRecords("resources.txt", 3);
        auto logs = readRecords("security_logs.txt", 6);

        int validUsersCount = 0;
        int validResourcesCount = 0;
        int deniedEvents = 0;

        for (const auto& fields : users) {
            if (validRole(fields[1])) {
                validUsersCount++;
            }
        }

        for (const auto& fields : resources) {
            if (validClassification(fields[1])) {
                validResourcesCount++;
            }
        }

        for (const auto& fields : logs) {
            if (fields[5] == "DENIED") {
                deniedEvents++;
            }
        }

        string json =
            "{\"totalUsers\":" + to_string(validUsersCount) +
            ",\"totalResources\":" + to_string(validResourcesCount) +
            ",\"totalLogs\":" + to_string(logs.size()) +
            ",\"deniedEvents\":" + to_string(deniedEvents) + "}";

        sendJson(response, json);
    });

    server.Get("/api/analytics", [](const httplib::Request& request,
                                    httplib::Response& response) {
        VigilXAuth::Session session;
        if (!requireAuthenticatedSession(request, response, session)) {
            return;
        }

        auto logs = readRecords("security_logs.txt", 6);

        int failedLogins = 0;
        int deniedAccesses = 0;
        int highRiskAssessments = 0;
        int successfulLogins = 0;

        map<string, int> failedByUsername;

        for (const auto& fields : logs) {
            if (isFailedLogin(fields)) {
                failedLogins++;
                failedByUsername[fields[2]]++;
            }

            if (isDeniedAccess(fields)) {
                deniedAccesses++;
            }

            if (isHighRiskAssessment(fields)) {
                highRiskAssessments++;
            }

            if (fields[4] == "LOGIN" && fields[5] == "SUCCESS") {
                successfulLogins++;
            }
        }

        int usersWithRepeatedFailures = 0;

        for (const auto& entry : failedByUsername) {
            if (entry.second >= 3) {
                usersWithRepeatedFailures++;
            }
        }

        string json =
            "{\"totalEvents\":" + to_string(logs.size()) +
            ",\"failedLogins\":" + to_string(failedLogins) +
            ",\"successfulLogins\":" + to_string(successfulLogins) +
            ",\"deniedAccesses\":" + to_string(deniedAccesses) +
            ",\"highRiskAssessments\":" + to_string(highRiskAssessments) +
            ",\"usersWithRepeatedFailures\":" +
                to_string(usersWithRepeatedFailures) + "}";

        sendJson(response, json);
    });

    server.Get("/api/alerts", [](const httplib::Request& request,
                                 httplib::Response& response) {
        VigilXAuth::Session session;
        if (!requireAuthenticatedSession(request, response, session)) {
            return;
        }

        auto logs = readRecords("security_logs.txt", 6);

        int deniedAccesses = 0;
        int highRiskAssessments = 0;

        map<string, int> failedByUsername;

        for (const auto& fields : logs) {
            if (isFailedLogin(fields)) {
                failedByUsername[fields[2]]++;
            }

            if (isDeniedAccess(fields)) {
                deniedAccesses++;
            }

            if (isHighRiskAssessment(fields)) {
                highRiskAssessments++;
            }
        }

        vector<string> alerts;

        for (const auto& entry : failedByUsername) {
            if (entry.second >= 3) {
                alerts.push_back(
                    alertJson(
                        "HIGH",
                        "REPEATED_FAILED_LOGINS",
                        "Username " + entry.first +
                            " has at least three recorded failed login attempts.",
                        entry.second
                    )
                );
            }
        }

        if (deniedAccesses >= 3) {
            alerts.push_back(
                alertJson(
                    "MEDIUM",
                    "REPEATED_DENIED_ACCESS",
                    "Three or more denied resource access events are recorded.",
                    deniedAccesses
                )
            );
        }

        if (highRiskAssessments > 0) {
            alerts.push_back(
                alertJson(
                    "HIGH",
                    "HIGH_RISK_ASSESSMENT",
                    "One or more high-risk assessments were recorded.",
                    highRiskAssessments
                )
            );
        }

        string json = "{\"totalAlerts\":" +
                      to_string(alerts.size()) +
                      ",\"alerts\":[";

        for (size_t i = 0; i < alerts.size(); i++) {
            if (i > 0) json += ",";
            json += alerts[i];
        }

        json += "]}";
        sendJson(response, json);
    });

    // New API: test a user's access to a resource.
    server.Post("/api/access-test", [](const httplib::Request& request,
                                       httplib::Response& response) {
        VigilXAuth::Session session;
        if (!requireAuthenticatedSession(request, response, session)) {
            return;
        }

        if (!request.has_param("resourceID")) {
            response.status = 400;
            sendJson(
                response,
                R"({"error":"resourceID is required."})"
            );
            return;
        }

        string resourceID = trim(request.get_param_value("resourceID"));

        if (resourceID.empty()) {
            response.status = 400;
            sendJson(
                response,
                R"({"error":"Resource ID cannot be empty."})"
            );
            return;
        }

        auto users = readRecords("users.txt", 3);
        auto resources = readRecords("resources.txt", 3);

        const vector<string>* selectedUser = nullptr;
        const vector<string>* selectedResource = nullptr;

        for (const auto& fields : users) {
            if (fields[2] == session.username &&
                fields[1] == session.role &&
                validRole(fields[1])) {
                selectedUser = &fields;
                break;
            }
        }

        for (const auto& fields : resources) {
            if (fields[0] == resourceID &&
                validClassification(fields[1])) {
                selectedResource = &fields;
                break;
            }
        }

        if (selectedUser == nullptr) {
            response.status = 404;
            sendJson(
                response,
                R"({"error":"User ID was not found or has an invalid role."})"
            );
            return;
        }

        if (selectedResource == nullptr) {
            response.status = 404;
            sendJson(
                response,
                R"({"error":"Resource ID was not found or has an invalid classification."})"
            );
            return;
        }

        const string username = (*selectedUser)[2];
        const string role = (*selectedUser)[1];
        const string classification = (*selectedResource)[1];
        const string resourceName = (*selectedResource)[2];

        int previousDenials = countPreviousDeniedRequests(username);
        int riskScore = calculateRiskScore(
            role,
            classification,
            previousDenials
        );

        string riskLevel = getRiskLevel(riskScore);
        bool allowed = hasAccessPermission(role, classification);
        string accessResult = allowed ? "GRANTED" : "DENIED";

        bool riskLogged = appendLog(
            username,
            role,
            "RISK_ASSESSMENT:" + resourceName,
            "SCORE_" + to_string(riskScore) + "_" + riskLevel
        );

        bool accessLogged = appendLog(
            username,
            role,
            "RESOURCE_ACCESS:" + resourceName,
            accessResult
        );

        if (!riskLogged || !accessLogged) {
            response.status = 500;
            sendJson(
                response,
                R"({"error":"Could not write the access test to security_logs.txt. Check the backend data path and file permissions."})"
            );
            return;
        }

        string json =
            "{\"userID\":" + safeJson((*selectedUser)[0]) +
            ",\"username\":" + safeJson(username) +
            ",\"role\":" + safeJson(role) +
            ",\"resourceID\":" + safeJson(resourceID) +
            ",\"resourceName\":" + safeJson(resourceName) +
            ",\"classification\":" + safeJson(classification) +
            ",\"riskScore\":" + to_string(riskScore) +
            ",\"riskLevel\":" + safeJson(riskLevel) +
            ",\"previousDenials\":" + to_string(previousDenials) +
            ",\"access\":" + safeJson(accessResult) +
            ",\"allowed\":" + string(allowed ? "true" : "false") +
            ",\"message\":" +
                safeJson(allowed
                    ? "Access granted by the role permission rules."
                    : "Access denied by the role permission rules.") +
            "}";

        sendJson(response, json);
    });

    cout << "=================================\n";
    cout << "      VIGILX C++ BACKEND\n";
    cout << "=================================\n";
    cout << "Dashboard:   http://127.0.0.1:8080\n";
    cout << "Health:      http://127.0.0.1:8080/api/health\n";
    cout << "Users:       http://127.0.0.1:8080/api/users\n";
    cout << "Resources:   http://127.0.0.1:8080/api/resources\n";
    cout << "Logs:        http://127.0.0.1:8080/api/logs\n";
    cout << "Stats:       http://127.0.0.1:8080/api/stats\n";
    cout << "Analytics:   http://127.0.0.1:8080/api/analytics\n";
    cout << "Alerts:      http://127.0.0.1:8080/api/alerts\n";
    cout << "Access test: POST /api/access-test\n";
    cout << "Press Ctrl+C to stop the server.\n";

    if (!server.listen("127.0.0.1", 18080)) {
        cerr << "Could not start server on port 8080.\n";
        return 1;
    }

    return 0;
}
