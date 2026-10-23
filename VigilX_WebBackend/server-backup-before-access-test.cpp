
#include "httplib.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

using namespace std;

const string DATA_PATH = "../";

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

        int validUsers = 0;
        int validResources = 0;
        int deniedEvents = 0;

        for (const auto& fields : users) {
            if (validRole(fields[1])) {
                validUsers++;
            }
        }

        for (const auto& fields : resources) {
            if (validClassification(fields[1])) {
                validResources++;
            }
        }

        for (const auto& fields : logs) {
            if (fields[5] == "DENIED") {
                deniedEvents++;
            }
        }

        string json =
            "{\"totalUsers\":" + to_string(validUsers) +
            ",\"totalResources\":" + to_string(validResources) +
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

        int failedLogins = 0;
        int deniedAccesses = 0;
        int highRiskAssessments = 0;

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

    cout << "=================================\n";
    cout << "      VIGILX C++ BACKEND\n";
    cout << "=================================\n";
    cout << "Dashboard:  http://127.0.0.1:8080\n";
    cout << "Health:     http://127.0.0.1:8080/api/health\n";
    cout << "Users:      http://127.0.0.1:8080/api/users\n";
    cout << "Resources:  http://127.0.0.1:8080/api/resources\n";
    cout << "Logs:       http://127.0.0.1:8080/api/logs\n";
    cout << "Stats:      http://127.0.0.1:8080/api/stats\n";
    cout << "Analytics:  http://127.0.0.1:8080/api/analytics\n";
    cout << "Alerts:     http://127.0.0.1:8080/api/alerts\n";
    cout << "Press Ctrl+C to stop the server.\n";

    if (!server.listen("127.0.0.1", 8080)) {
        cerr << "Could not start server on port 8080.\n";
        return 1;
    }

    return 0;
}
