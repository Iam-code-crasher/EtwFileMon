#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <mutex>
#include <string>
#include <memory>
#include "Common.h"


SERVICE_STATUS gServiceStatus = { 0 };
SERVICE_STATUS_HANDLE gServiceStatusHandle = NULL;
HANDLE gServiceStopEvent = INVALID_HANDLE_VALUE;

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD);
void InstallService();
void UninstallService();

#define SERVICE_NAME  _T("EtwService")
extern HANDLE hProcess;  // Declaration of external variable

// Function to report the current service status
void ReportServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint) {
    static DWORD dwCheckPoint = 1;

    gServiceStatus.dwCurrentState = dwCurrentState;
    gServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    gServiceStatus.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING)
        gServiceStatus.dwControlsAccepted = 0;
    else
        gServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
        gServiceStatus.dwCheckPoint = 0;
    else
        gServiceStatus.dwCheckPoint = dwCheckPoint++;

    SetServiceStatus(gServiceStatusHandle, &gServiceStatus);
}

SERVICE_STATUS ServiceStatus;
// Main service entry function
void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    OutputDebugStringW(_T("Starting Service Main"));
    gServiceStatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler); // Use the 'W' version for wide string consistency
    if (!gServiceStatusHandle) {
        WriteDebugLogWithError(L"Failed to register service control handler", GetLastError());
        return;
    }

    // Initial service state setup
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    ServiceStatus.dwWin32ExitCode = 0;
    ServiceStatus.dwServiceSpecificExitCode = 0;
    ServiceStatus.dwCheckPoint = 0;
    ServiceStatus.dwWaitHint = 0;

    SetServiceStatus(gServiceStatusHandle, &ServiceStatus);

    // Running state
    ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(gServiceStatusHandle, &ServiceStatus);

    //Start Monitoring Process
    StartMonitoringProcess();

    // Create a stop event to signal service stop
    gServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (gServiceStopEvent == NULL) {
        WriteDebugLogWithError(L"Failed to create stop event", GetLastError());
        ReportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    // Start your trace or monitoring here (e.g., start your ETW logic)
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);
    OutputDebugStringW(_T("Service running, waiting for stop event"));

    // Wait for the stop signal
    WaitForSingleObject(gServiceStopEvent, INFINITE);

    // Clean up and stop
    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
    CloseHandle(gServiceStopEvent); // Close the stop event handle
}

void WINAPI ServiceCtrlHandler(DWORD request) {
    switch (request) {
    case SERVICE_CONTROL_STOP:
        OutputDebugStringW(_T("Service is stopping..."));

        // Stop the launched executable if it's still running
        if (hProcess != NULL) {
            OutputDebugStringW(_T("Terminating child process..."));

            // Gracefully terminate the process (if possible) or force terminate it
            if (!TerminateProcess(hProcess, 0)) {
                OutputDebugStringW(_T("Failed to terminate child process."));
            }
            else {
                OutputDebugStringW(_T("Child process terminated successfully."));
            }

            CloseHandle(hProcess);
            hProcess = NULL;
        }

        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
        ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
        // Signal the service to stop
        SetEvent(gServiceStopEvent);
        OutputDebugStringW(_T("Service stopped"));
        return;

    default:
        break;
    }
}



void InstallService() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL) {
        WriteDebugLogWithError(L"OpenSCManager failed with error: ", GetLastError());
        return;
    }

    // Get the directory of the service executable and build the path to the monitoring executable
    std::wstring serviceExePath = L"\"" + GetExecutableDirectory() + L"\\EtwService.exe\"";

    SC_HANDLE hService = CreateService(
        hSCManager,                  // SCM database
        SERVICE_NAME,                // Name of service
        SERVICE_NAME,                // Display name of the service
        SERVICE_ALL_ACCESS,          // Desired access
        SERVICE_WIN32_OWN_PROCESS,   // Service type
        SERVICE_AUTO_START,          // Start type (automatic start)
        SERVICE_ERROR_NORMAL,        // Error control type
        serviceExePath.c_str(),             // Path to the service executable
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);

    if (hService == NULL) {
        WriteDebugLogWithError(L"CreateService failed with error: ", GetLastError());
        CloseServiceHandle(hSCManager);
        return;
    }

    WriteDebugLogWithError(L"Service installed successfully.", GetLastError());

    // Cleanup
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}


// Function to uninstall the service
void UninstallService() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        WriteDebugLogWithError(L"OpenSCManager failed", GetLastError());
        return;
    }

    SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, DELETE);
    if (hService == NULL) {
        WriteDebugLogWithError(L"OpenService failed", GetLastError());
        CloseServiceHandle(hSCManager);
        return;
    }

    if (!DeleteService(hService)) {
        WriteDebugLogWithError(L"DeleteService failed", GetLastError());
    }
    else {
        OutputDebugStringW(L"Service uninstalled successfully.");
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}

// Main entry point
int _tmain(int argc, TCHAR* argv[]) {

    if (argc > 1) {
        if (_tcscmp(argv[1], _T("--install")) == 0) {
            InstallService();
            return 0;
        }
        else if (_tcscmp(argv[1], _T("--uninstall")) == 0) {
            UninstallService();
            return 0;
        }
    }


    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (!StartServiceCtrlDispatcher(ServiceTable)) {
        WriteDebugLogWithError(L"StartServiceCtrlDispatcher failed", GetLastError());
    }
    return 0;
}
