#include <iostream>
#include <fstream>
#include <sstream>
#include "third_party/httplib.h"
#include "third_party/json.hpp"
#include "SecurityEngine.hpp"

using json = nlohmann::json;

int main() {
    // Initialize Security Engine Singleton
    auto& engine = SecurityEngine::getInstance();
    httplib::Server svr;

    // Serve static frontend files from the "web" directory
    svr.set_mount_point("/", "./web");

    // 1. POST /api/login Endpoint
    svr.Post("/api/login", [](const httplib::Request& req, httplib::Response& res) {
        try {
            auto data = json::parse(req.body);
            std::string username = data.value("username", "");
            std::string password = data.value("password", "");

            User* user = SecurityEngine::getInstance().authenticate(username, password);
            json resp;
            if (user) {
                resp["status"] = "success";
                resp["username"] = user->getUsername();
                resp["role"] = user->getRoleName();
                resp["locked"] = user->isLocked();
            } else {
                resp["status"] = "error";
                resp["message"] = "Invalid credentials or user not found.";
            }
            res.set_content(resp.dump(), "application/json");
        } catch (...) {
            res.status = 400;
            res.set_content("{\"status\":\"error\",\"message\":\"Invalid JSON request\"}", "application/json");
        }
    });

    // 2. POST /api/access Endpoint (Risk Assessment & RBAC)
    svr.Post("/api/access", [](const httplib::Request& req, httplib::Response& res) {
        try {
            auto data = json::parse(req.body);
            std::string username = data.value("username", "");
            std::string resourceId = data.value("resourceId", "");
            int currentHour = data.value("currentHour", 12);
            int requestFrequency = data.value("requestFrequency", 1);
            bool unusualPattern = data.value("isUnusualPattern", false);

            AccessContext context{currentHour, requestFrequency, unusualPattern};

            auto result = SecurityEngine::getInstance().evaluateAccess(username, resourceId, context);

            json resp;
            resp["decision"] = result.decision;
            resp["severity"] = result.severity;
            resp["riskScore"] = result.riskScore;
            resp["message"] = result.message;

            res.set_content(resp.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            res.set_content(json({{"error", e.what()}}).dump(), "application/json");
        }
    });

    // 3. GET /api/logs Endpoint
    svr.Get("/api/logs", [](const httplib::Request&, httplib::Response& res) {
        std::ifstream logFile("data/security_logs.txt");
        std::string logs((std::istreambuf_iterator<char>(logFile)), std::istreambuf_iterator<char>());
        
        json resp;
        resp["logs"] = logs.empty() ? "No security logs recorded yet." : logs;
        res.set_content(resp.dump(), "application/json");
    });

    std::cout << "[VigilX Engine] Starting Security Operations Server on http://localhost:8080 ...\n";
    svr.listen("0.0.0.0", 8080);

    return 0;
}