#pragma once
#include <fstream>
#include <string>
#include <mutex>

// Global file stream and mutex for thread-safe logging
std::ofstream logFile("debug.log", std::ios::app);
std::mutex logMutex;

// Logger function
void LogMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(logMutex); // Ensure thread safety
    logFile << message << std::endl;
}
