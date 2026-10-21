#include "DataValidationRecovery.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <limits>
#include <filesystem>
using namespace std;
namespace fs = std::filesystem;
namespace {
const vector<string> files={"users.txt","resources.txt","security_logs.txt","incidents.txt","permissions.txt","policies.txt","security_cases.txt","alerts.txt"};
int separators(const string& line,char delim='|'){int n=0;for(char c:line)if(c==delim)++n;return n;}
int expected(const string& name){if(name=="users.txt")return 4; if(name=="resources.txt")return 3; if(name=="security_logs.txt")return 5; if(name=="incidents.txt")return 4; if(name=="permissions.txt")return 2; if(name=="policies.txt")return 3; if(name=="security_cases.txt")return 5; if(name=="alerts.txt")return 6; return -1;}
}
DataValidationRecovery::DataValidationRecovery(SecurityLogger& l):logger(l){}
void DataValidationRecovery::validateFiles() const {
 cout<<"\n===== LOCAL DATA VALIDATION =====\n";
 for(const auto& name:files){ if(!fs::exists(name)){cout<<name<<": NOT PRESENT (may be created when the related feature is first used)\n";continue;}
  ifstream in(name);string line;int total=0,valid=0,blank=0;while(getline(in,line)){if(line.empty()){++blank;continue;}++total;int exp=expected(name);if(exp<0||separators(line)>=exp)++valid;}
  cout<<name<<": lines="<<total<<", basic-format-valid="<<valid<<", blank="<<blank;
  if(valid==total)cout<<" [PASS]\n";else cout<<" [REVIEW]\n";
 }
 cout<<"Note: this is a basic delimiter/line check, not a complete semantic validator.\n";
}
void DataValidationRecovery::createBackups(const string& u,const string& r){int saved=0;for(const auto& name:files){if(!fs::exists(name))continue;ifstream in(name,ios::binary);ofstream out(name+".bak",ios::binary|ios::trunc);if(in&&out){out<<in.rdbuf();if(out)++saved;}}logger.logEvent(u,r,"DATA_BACKUP","SUCCESS_FILES_"+to_string(saved));cout<<"Backup operation finished. Files copied: "<<saved<<". Backups use the .bak suffix.\n";}
void DataValidationRecovery::restoreMissing(const string& u,const string& r){int restored=0;for(const auto& name:files){if(fs::exists(name))continue;string backup=name+".bak";if(!fs::exists(backup))continue;cout<<"Restore missing "<<name<<" from "<<backup<<"? (y/n): ";string answer;getline(cin,answer);if(answer!="y"&&answer!="Y")continue;ifstream in(backup,ios::binary);ofstream out(name,ios::binary|ios::trunc);if(in&&out){out<<in.rdbuf();if(out)++restored;}}
 logger.logEvent(u,r,"DATA_RECOVERY","RESTORED_"+to_string(restored));cout<<"Recovery finished. Missing files restored: "<<restored<<". Existing files were not overwritten.\n";}
void DataValidationRecovery::runMenu(const string& u,const string& r){if(r!="Admin"&&r!="SecurityAnalyst"){cout<<"Access denied.\n";logger.logEvent(u,r,"DATA_VALIDATION_RECOVERY","DENIED_NOT_AUTHORIZED");return;}int c;do{cout<<"\n===== DATA VALIDATION & RECOVERY =====\n1. Validate Local Data Files\n2. Create .bak Backups\n3. Restore Missing Files from .bak (asks before each restore)\n0. Return\nChoice: ";if(!(cin>>c)){cin.clear();cin.ignore(numeric_limits<streamsize>::max(),'\n');cout<<"Invalid input.\n";continue;}cin.ignore(numeric_limits<streamsize>::max(),'\n');switch(c){case 1:validateFiles();break;case 2:createBackups(u,r);break;case 3:restoreMissing(u,r);break;case 0:break;default:cout<<"Invalid choice.\n";}}while(c!=0);}
