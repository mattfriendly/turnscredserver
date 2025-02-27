
::::::::::::::
turnscredserver.cpp
::::::::::::::
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <string>
#include <csignal>
#include <ctime>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <iostream>
#include <cstring>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cstdlib>

const std::string SHARED_SECRET = "<your secret here>";
const std::string CERT_FILE = "/etc/ssl/turnscredserver/cert.pem";
const std::string KEY_FILE = "/etc/ssl/turnscredserver/key.pem";
const std::string LOG_FILE_PATH = "/var/log/turnserver/turnscred.log";

// Function declarations
std::string getRandomWordFromDictionary();
std::string generate_turn_credentials(const std::string& client_ip);
void handleSigTerm(int signum);
void handleSigInt(int signum);

httplib::SSLServer* globalServer = nullptr;

void handleSigInt(int signum) {
    std::ofstream logFile;
    logFile.open(LOG_FILE_PATH, std::ios::app);
    if (logFile.is_open()) {
        auto now = std::time(nullptr);
        auto localTime = *std::localtime(&now);
        logFile << std::put_time(&localTime, "[%Y-%m-%d %H:%M:%S]")
                << " SIGINT received, shutting down server." << std::endl;
        logFile.close();
    }

    if (globalServer) {
        globalServer->stop();
    }

    exit(0);  // Exit the program
}

int main() {
    httplib::SSLServer svr(CERT_FILE.c_str(), KEY_FILE.c_str());
    globalServer = &svr; // Set the global server instance

    std::signal(SIGTERM, handleSigTerm);
    std::signal(SIGINT, handleSigInt);  // Register SIGINT handler

    svr.Get("/credentials", [](const httplib::Request& req, httplib::Response& res) {
        std::string client_ip = req.remote_addr;  // Get the client's IP address
        std::string response_content = generate_turn_credentials(client_ip);
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept");
        res.set_content(response_content, "application/json");
    });

    std::cout << "Starting HTTPS server on port 3030..." << std::endl;
    svr.listen("0.0.0.0", 3030);

    return 0;
}

std::string generate_turn_credentials(const std::string& client_ip) {
    // Get the current time
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);

    // Create a string stream for formatting the time
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");  // Format the time as YYYY-MM-DD HH:MM:SS
    std::string str_time = oss.str();

    std::cout << "[DEBUG] Generating TURN credentials for IP: " << client_ip << std::endl;

    // Use the "obscure" username base as in the Python version
    std::string username_base = "obscure";

    // Credential expiration time (e.g., 1 hour from now)
    std::string timestamp = std::to_string(std::time(nullptr) + 3600);
    std::string temp_username = timestamp + ":" + username_base;

    unsigned char* digest = HMAC(EVP_sha1(), SHARED_SECRET.c_str(), SHARED_SECRET.length(), (unsigned char*)temp_username.c_str(), temp_username.length(), NULL,
NULL);

    char* base64_encoded = (char*)malloc(EVP_ENCODE_LENGTH(20));
    EVP_EncodeBlock((unsigned char*)base64_encoded, digest, 20);

    std::string temp_password(base64_encoded);
    free(base64_encoded);

    std::string credentials = "{\"username\":\"" + temp_username + "\",\"password\":\"" + temp_password + "\"}";

    // Log the credentials, client IP, and timestamp to a file
    std::ofstream logFile;
    logFile.open(LOG_FILE_PATH, std::ios::app);  // Open in append mode
    if (logFile.is_open()) {
        logFile << "[" << str_time << "] IP: " << client_ip << ", Credentials: " << credentials << std::endl;
        logFile.close();
    } else {
        std::cerr << "Error: Unable to open log file." << std::endl;
    }

    return credentials;
}

void handleSigTerm(int signum) {
    // Log the shutdown
    std::ofstream logFile;
    logFile.open(LOG_FILE_PATH, std::ios::app);  // Open in append mode
    if (logFile.is_open()) {
        auto now = std::time(nullptr);
        auto localTime = *std::localtime(&now);
        logFile << std::put_time(&localTime, "[%Y-%m-%d %H:%M:%S]")
                << " SIGTERM received, shutting down server." << std::endl;
        logFile.close();
    }

    if (globalServer) {
        globalServer->stop();
    }

    exit(0);  // Exit the program
}
