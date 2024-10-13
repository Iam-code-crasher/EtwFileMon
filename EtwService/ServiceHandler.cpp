#include "Common.h"

// Function to start the monitoring process
void StartMonitoringProcess() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Get the directory of the service executable and build the path to the monitoring executable
    std::wstring exePath = GetExecutableDirectory() + L"\\EtwFileMonitor.exe --start";

    if (CreateProcess(NULL, (LPWSTR)exePath.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        WriteDebugLogWithError(L"CreateProcess failed.", GetLastError());
    }
}

// Function to stop the monitoring process
void StopMonitoringProcess() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Get the directory of the service executable and build the path to the monitoring executable
    std::wstring exePath = GetExecutableDirectory() + L"\\EtwFileMonitor.exe --stop";

    if (CreateProcess(NULL, (LPWSTR)exePath.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        WriteDebugLogWithError(L"Failed to stop the monitoring process.", GetLastError());
    }
}
