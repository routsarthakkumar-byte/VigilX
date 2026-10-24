
#include "httplib.h"

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

using namespace std;

const string DATA_PATH = "../";
mutex logMutex;

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

int main() {
    httplib::Server server;

    if (!server.set_mount_point("/", "./public")) {
        cerr << "Could not mount the public folder.\n";
        return 1;
    }

    server.Get("/api/health", [](const httplib::Request&,
                                 httplib::Response& response) {
        sendJson(
            response,
            R"({"status":"ok","service":"VigilX","language":"C++"})"
        );
    });

    server.Get("/api/users", [](const httplib::Request&,
                                httplib::Response& response) {
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

    server.Get("/api/resources", [](const httplib::Request&,
                                    httplib::Response& response) {
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

    server.Get("/api/logs", [](const httplib::Request&,
                               httplib::Response& response) {
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

    server.Get("/api/stats", [](const httplib::Request&,
                                httplib::Response& response) {
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

    server.Get("/api/analytics", [](const httplib::Request&,
                                    httplib::Response& response) {
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

    server.Get("/api/alerts", [](const httplib::Request&,
                                 httplib::Response& response) {
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
        if (!request.has_param("userID") ||
            !request.has_param("resourceID")) {
            response.status = 400;
            sendJson(
                response,
                R"({"error":"Both userID and resourceID are required."})"
            );
            return;
        }

        string userID = trim(request.get_param_value("userID"));
        string resourceID = trim(request.get_param_value("resourceID"));

        if (userID.empty() || resourceID.empty()) {
            response.status = 400;
            sendJson(
                response,
                R"({"error":"User ID and resource ID cannot be empty."})"
            );
            return;
        }

        auto users = readRecords("users.txt", 3);
        auto resources = readRecords("resources.txt", 3);

        const vector<string>* selectedUser = nullptr;
        const vector<string>* selectedResource = nullptr;

        for (const auto& fields : users) {
            if (fields[0] == userID && validRole(fields[1])) {
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
            "{\"userID\":" + safeJson(userID) +
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

    if (!server.listen("127.0.0.1", 8080)) {
        cerr << "Could not start server on port 8080.\n";
        return 1;
    }

    return 0;
}
