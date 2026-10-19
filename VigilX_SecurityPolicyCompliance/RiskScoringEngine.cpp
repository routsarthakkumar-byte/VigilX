#include "RiskScoringEngine.h"
#include <algorithm>
#include <iostream>
using namespace std;
int RiskScoringEngine::calculateRiskScore(const User& user,const Resource& resource,int previousDenials) const {int score=0;string role=user.getRole(),level=resource.getClassification();if((role=="Employee"&&level=="Confidential")||(role=="Guest"&&level!="Public"))score+=40;score+=min(previousDenials*15,60);return min(score,100);}
string RiskScoringEngine::getRiskLevel(int score) const {if(score<30)return "LOW";if(score<60)return "MEDIUM";return "HIGH";}
void RiskScoringEngine::displayRiskAssessment(int score) const {cout<<"\n========== RISK ASSESSMENT ==========\nRisk Score : "<<score<<"/100\nRisk Level : "<<getRiskLevel(score)<<"\n=====================================\n";}
