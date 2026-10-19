#include "Utils.h"
#include <sstream>
#include <algorithm>
using namespace std;
string trim(const string& value) {
    size_t start = value.find_first_not_of(" \t\r\n");
    if (start == string::npos) return "";
    size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}
string cleanField(string value) {
    for (char& ch : value) if (ch == '|' || ch == '\n' || ch == '\r') ch = '_';
    return value;
}
vector<string> splitLine(const string& line) {
    vector<string> fields; stringstream ss(line); string field;
    while (getline(ss, field, '|')) fields.push_back(trim(field));
    return fields;
}
