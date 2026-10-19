#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <fstream>
#include <string>
#include <ctime>
#include <iostream>

class Logger {
private:
    std::string logFilePath_;

public:
    Logger(std::string logFilePath = "data/security_logs.txt") 
        : logFilePath_(std::move(logFilePath)) {}

    void logEvent(const std::string& username, const std::string& resourceName, 
                  const std::string& decision, const std::string& severity, double riskScore) {
        std::ofstream logFile(logFilePath_, std::ios::app);
        if (logFile.is_open()) {
            std::time_t now = std::time(nullptr);
            char timestamp[64];
            std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

            logFile << "[" << timestamp << "] "
                    << "User: " << username << " | "
                    << "Resource: " << resourceName << " | "
                    << "Decision: " << decision << " | "
                    << "Severity: " << severity << " | "
                    << "Risk Score: " << riskScore << "\n";
            
            logFile.close();
        } else {
            std::cerr << "[LOGGER ERROR] Unable to open security log file at: " << logFilePath_ << "\n";
        }
    }
};

#endif // LOGGER_HPP