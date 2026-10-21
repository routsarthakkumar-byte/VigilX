#pragma once
#include "User.h"
#include "Resource.h"
class RiskScoringEngine {
public: int calculateRiskScore(const User& user,const Resource& resource,int previousDenials) const; std::string getRiskLevel(int score) const; void displayRiskAssessment(int score) const;
};
