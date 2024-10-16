#pragma once
#include <windows.h>
#include <string>
#include <fstream>
#include <string>
#include <mutex>

std::wstring GetExecutableDirectory();
void WriteDebugLogWithError(const std::wstring& message, DWORD errorCode);
void StartMonitoringProcess();