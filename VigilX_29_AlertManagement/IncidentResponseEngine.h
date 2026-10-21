#pragma once
#include "SecurityLogger.h"
#include <string>
#include <vector>

struct Incident {
    int id = 0;
    std::string timestamp;
    std::string username;
    std::string type;
    std::string severity;
    int sourceEventID = 0;
    std::string status;
    std::string responseAction;
};

class IncidentResponseEngine {
private:
    SecurityLogger& logger;
    std::string filename = "incidents.txt";
    std::vector<Incident> readIncidents() const;
    bool saveIncident(const Incident& incident) const;
    bool alreadyExists(const std::vector<Incident>& incidents, const std::string& username,
                       const std::string& type, int sourceEventID) const;
    void detectAndCreateIncidents();
    void viewIncidents() const;
    void updateIncidentStatus();
public:
    explicit IncidentResponseEngine(SecurityLogger& securityLogger);
    void runMenu();
};
