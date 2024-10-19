#include "Common.h"
#include <string>

HANDLE hProcess = NULL;  // Definition of global variable
// Function to start the monitoring process
void StartMonitoringProcess() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Get the directory of the service executable and build the path to the monitoring executable
    std::wstring exePath =std::wstring(L"\"") + GetExecutableDirectory() + std::wstring(L"\\EtwFileMonitor.exe\"") + L" --start";
    std::wstring workingDir = GetExecutableDirectory();
    WriteDebugLogWithError(std::wstring(L"Launching:") + exePath, 0);
    WriteDebugLogWithError(std::wstring(L"Working Dir:") + workingDir, 0);

    if (!CreateProcess(NULL, (LPWSTR)exePath.c_str(), NULL, NULL, FALSE, 0, NULL, workingDir.c_str(), &si, &pi)) {
       
        return;
    }

    hProcess = pi.hProcess;  // Store the process handle for termination
    WriteDebugLogWithError(L"Executable launched successfully.", 0);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

