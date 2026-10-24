#include <openssl/rand.h>

#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;

string toHex(const unsigned char* data, size_t length) {
    ostringstream output;
    output << hex << setfill('0');

    for (size_t i = 0; i < length; ++i) {
        output << setw(2) << static_cast<unsigned int>(data[i]);
    }

    return output.str();
}

string generateSessionToken() {
    array<unsigned char, 32> bytes{};

    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        return "";
    }

    return toHex(bytes.data(), bytes.size());
}

string extractSessionToken(const string& cookieHeader) {
    const string key = "VigilXSession=";
    size_t position = cookieHeader.find(key);

    if (position == string::npos) {
        return "";
    }

    position += key.size();
    size_t end = cookieHeader.find(';', position);

    string token = cookieHeader.substr(
        position,
        end == string::npos ? string::npos : end - position
    );

    if (token.size() != 64) {
        return "";
    }

    for (unsigned char c : token) {
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f'))) {
            return "";
        }
    }

    return token;
}

int main() {
    string first = generateSessionToken();
    string second = generateSessionToken();

    if (first.size() != 64 || second.size() != 64) {
        cerr << "Session token generation failed.\n";
        return 1;
    }

    if (first == second) {
        cerr << "Session tokens unexpectedly matched.\n";
        return 2;
    }

    string cookie = "theme=dark; VigilXSession=" + first + "; Path=/";
    string extracted = extractSessionToken(cookie);

    if (extracted != first) {
        cerr << "Cookie extraction failed.\n";
        return 3;
    }

    if (!extractSessionToken("theme=dark").empty()) {
        cerr << "Missing-cookie test failed.\n";
        return 4;
    }

    cout << "Secure session token generation: PASS\n";
    cout << "Distinct token test: PASS\n";
    cout << "Cookie extraction test: PASS\n";
    cout << "Missing-cookie test: PASS\n";

    return 0;
}
