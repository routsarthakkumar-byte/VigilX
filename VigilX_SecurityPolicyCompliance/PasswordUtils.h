#pragma once
#include <string>
std::string generateSalt();
std::string sha256(const std::string& input);
std::string hashPassword(const std::string& password, const std::string& salt);
