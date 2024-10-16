#include "Common.h"

HANDLE hProcess = NULL;  // Definition of global variable
// Function to start the monitoring process
void StartMonitoringProcess() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Get the directory of the service executable and build the path to the monitoring executable
    std::wstring exePath = GetExecutableDirectory() + L"\\EtwFileMonitor.exe --start";
    std::wstring workingDir = GetExecutableDirectory();

    if (!CreateProcess(NULL, (LPWSTR)exePath.c_str(), NULL, NULL, FALSE, 0, NULL, workingDir.c_str(), &si, &pi)) {
        WriteDebugLogWithError(L"Failed to launch executable.", GetLastError());
        return;
    }

    hProcess = pi.hProcess;  // Store the process handle for termination
    WriteDebugLogWithError(L"Executable launched successfully.", 0);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

