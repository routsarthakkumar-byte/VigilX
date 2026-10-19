#pragma once
#include <string>
class Resource {
private: int resourceID; std::string resourceName; std::string classification;
public:
    Resource(int id, const std::string& name, const std::string& level);
    int getResourceID() const; std::string getResourceName() const; std::string getClassification() const; void display() const;
};
