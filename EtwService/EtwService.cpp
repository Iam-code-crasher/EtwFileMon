#include <windows.h>
#include <tchar.h>
#include <iostream>

SERVICE_STATUS gServiceStatus = { 0 };
SERVICE_STATUS_HANDLE gServiceStatusHandle = NULL;
HANDLE gServiceStopEvent = INVALID_HANDLE_VALUE;

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
void WINAPI ServiceCtrlHandler(DWORD);
void InstallService();
void UninstallService();
void RunService();

#define SERVICE_NAME  _T("EtwService")

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

void WINAPI ServiceMain(DWORD argc, LPTSTR* argv) {
    gServiceStatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (!gServiceStatusHandle) {
        return;
    }

    gServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gServiceStatus.dwServiceSpecificExitCode = 0;

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    // Create a stop event to signal service stop
    gServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (gServiceStopEvent == NULL) {
        ReportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    // Start your trace or monitoring here (e.g., start your ETW logic)
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // Wait for the stop signal
    WaitForSingleObject(gServiceStopEvent, INFINITE);

    // Clean up and stop
    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
    case SERVICE_CONTROL_STOP:
        if (gServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;

        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

        // Signal the service to stop
        SetEvent(gServiceStopEvent);

        ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
        break;

    default:
        break;
    }
}

void InstallService() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hSCManager == NULL) {
        std::cerr << "OpenSCManager failed with error: " << GetLastError() << std::endl;
        return;
    }

    SC_HANDLE hService = CreateService(
        hSCManager,                  // SCM database
        SERVICE_NAME,                // Name of service
        SERVICE_NAME,                // Service name to display
        SERVICE_ALL_ACCESS,          // Desired access
        SERVICE_WIN32_OWN_PROCESS,   // Service type
        SERVICE_AUTO_START,          // Start type
        SERVICE_ERROR_NORMAL,        // Error control type
        _T("EtwFileMonitor.exe"), // Path to service binary
        NULL,                        // No load ordering group
        NULL,                        // No tag identifier
        NULL,                        // No dependencies
        NULL,                        // LocalSystem account
        NULL);                       // No password

    if (hService == NULL) {
        std::cerr << "CreateService failed with error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return;
    }

    std::cout << "Service installed successfully." << std::endl;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}

void UninstallService() {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        std::cerr << "OpenSCManager failed with error: " << GetLastError() << std::endl;
        return;
    }

    SC_HANDLE hService = OpenService(hSCManager, SERVICE_NAME, DELETE);
    if (hService == NULL) {
        std::cerr << "OpenService failed with error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return;
    }

    if (!DeleteService(hService)) {
        std::cerr << "DeleteService failed with error: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "Service uninstalled successfully." << std::endl;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
}


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
        std::cerr << "StartServiceCtrlDispatcher failed with error: " << GetLastError() << std::endl;
    }

    return 0;
}
