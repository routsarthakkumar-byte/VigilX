#include "httplib.h"
#include <iostream>

int main() {
    httplib::Server server;

    if (!server.set_mount_point("/", "./public")) {
        std::cerr << "Could not mount the public folder.\n";
        return 1;
    }

    server.Get("/api/health", [](const httplib::Request&,
                                 httplib::Response& response) {
        response.set_content(
            R"({"status":"ok","service":"VigilX","language":"C++"})",
            "application/json"
        );
    });

    std::cout << "=================================\n";
    std::cout << "      VIGILX C++ BACKEND\n";
    std::cout << "=================================\n";
    std::cout << "Dashboard: http://127.0.0.1:8080\n";
    std::cout << "Health:    http://127.0.0.1:8080/api/health\n";
    std::cout << "Press Ctrl+C to stop the server.\n";

    if (!server.listen("127.0.0.1", 8080)) {
        std::cerr << "Could not start server on port 8080.\n";
        return 1;
    }

    return 0;
}
