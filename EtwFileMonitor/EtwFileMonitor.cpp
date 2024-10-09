// this code will work only when compiled as 64-bit code, and on Windows 10
// older Windows version might require different structure definitions

#define NOMINMAX
#define INITGUID
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <iostream>
#include <fstream>
#include <iomanip>  // For formatting
#include <wchar.h>  // For working with wide character strings
#pragma comment (lib, "shell32.lib")
#pragma comment (lib, "advapi32.lib")

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <thread>
#include <string>
#include <sstream>  // For string stream
#include <map>

// Global map to store the mapping between FileObject and file path
std::map<uint64_t, std::wstring> fileObjectToPathMap;


static const GUID FileIoGuid = { 0x90cbdc39, 0x4a3e, 0x11d1, { 0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3 } };
static const GUID PerfInfoGuid = { 0xce1dbfb4, 0x137e, 0x4da6, { 0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc } };

//From https://github.com/winsiderss/systeminformer/blob/934a81307e0a1bbdc5d9390889fdea531ecc78ea/phnt/include/ntwmi.h#L908

#define PERFINFO_LOG_TYPE_FILE_IO_CREATE             0x40
#define PERFINFO_LOG_TYPE_FILE_IO_CLEANUP            0x41
#define PERFINFO_LOG_TYPE_FILE_IO_CLOSE              0x42
#define PERFINFO_LOG_TYPE_FILE_IO_READ               0x43
#define PERFINFO_LOG_TYPE_FILE_IO_WRITE              0x44
#define PERFINFO_LOG_TYPE_FILE_IO_SET_INFORMATION    0x45
#define PERFINFO_LOG_TYPE_FILE_IO_DELETE             0x46
#define PERFINFO_LOG_TYPE_FILE_IO_RENAME             0x47


// structures from "C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\km\wmicore.mof" (in Windows DDK)
struct FileIo_Create
{
    uint64_t IrpPtr;
    uint64_t FileObject;
    uint32_t TTID;
    uint32_t CreateOptions;
    uint32_t FileAttributes;
    uint32_t ShareAccess;
    wchar_t OpenPath[1000];
};

struct
{
    EVENT_TRACE_PROPERTIES Properties;
    WCHAR SessionName[1024];
}
static gTrace;

static TRACEHANDLE gTraceHandle;
static HANDLE gTraceThread;
static DWORD gProcessFilter;

// Global variables for filtering
std::wstring gDirectoryFilter;

// Function to read configuration (pid and directory) from a file
bool ReadConfig(const std::string& configFilePath) {
    std::ifstream configFile(configFilePath);
    if (!configFile.is_open()) {
        std::cerr << "Error: Could not open configuration file!" << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(configFile, line)) {

        if (line.find("directory=") == 0) {
            gDirectoryFilter = std::wstring(line.begin() + 10, line.end()); // Extract directory
        }
    }

    configFile.close();
    return true;
}


// check if current process is elevated
static BOOL IsElevated(void)
{
    BOOL result = FALSE;

    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size))
        {
            result = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }

    return result;
}

// enables profiling privilege
static BOOL EnableProfilePrivilge(void)
{
    BOOL result = FALSE;

    HANDLE token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
    {
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_SYSTEM_PROFILE_NAME, &luid))
        {
            TOKEN_PRIVILEGES tp;
            {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            }
            if (AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL))
            {
                result = TRUE;
            }
        }
        CloseHandle(token);
    }

    return result;
}
// Function to convert NT-style device paths to DOS-style paths
std::wstring ConvertNtPathToDosPath(const std::wstring& ntPath) {
    // Buffer to store the result of QueryDosDeviceW
    wchar_t deviceName[MAX_PATH] = { 0 };
    wchar_t driveLetter[3] = L"A:";
    std::wstring dosPath = ntPath;

    // Iterate through the possible drive letters (A-Z)
    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
        driveLetter[0] = letter;

        // QueryDosDeviceW maps DOS drive letters to their NT device names
        if (QueryDosDeviceW(driveLetter, deviceName, MAX_PATH)) {
            size_t deviceNameLen = wcslen(deviceName);

            // If the NT path starts with the device name, replace it with the drive letter
            if (ntPath.find(deviceName) == 0) {
                dosPath.replace(0, deviceNameLen, driveLetter);
                break;
            }
        }
    }

    return dosPath; // Return the converted DOS path
}

struct FileIo_Read {
    uint64_t IrpPtr;
    uint64_t FileObject;
    uint32_t TTID;
    uint32_t Length;
    uint64_t Offset;
};

struct FileIo_Write {
    uint64_t IrpPtr;
    uint64_t FileObject;
    uint32_t TTID;
    uint32_t Length;
    uint64_t Offset;
};

struct FileIo_Delete {
    uint64_t IrpPtr;
    uint64_t FileObject;
    uint32_t TTID;
};

struct FileIo_Rename {
    uint64_t IrpPtr;
    uint64_t FileObject;
    uint32_t TTID;
    wchar_t NewName[1000];
};

// Function to log events
void WriteToLog(uint64_t IrpPtr, uint64_t FileObject, const std::wstring& filePath, const std::string& operation, uint32_t length = 0, uint64_t offset = 0) {
    std::ofstream logFile("EtwFileMonitor.log", std::ios_base::app);
    if (!logFile.is_open()) {
        std::cerr << "Error: Could not open log file!" << std::endl;
        return;
    }

    logFile << "Operation: " << operation
        << ", File Path: " << std::string(filePath.begin(), filePath.end())
        << ", Length: " << length
        << ", Offset: " << offset
        << std::endl;

    logFile.close();
}

// Function to handle File Create events
void HandleFileCreate(EVENT_RECORD* event) {
    struct FileIo_Create* data = (FileIo_Create*)event->UserData;

    // Convert NT path to DOS path
    std::wstring ntPath(data->OpenPath);
    std::wstring dosPath = ConvertNtPathToDosPath(ntPath);

    // Store the path in the map using FileObject as the key
    fileObjectToPathMap[data->IrpPtr] = dosPath;

    // Log the file creation event
    WriteToLog(data->IrpPtr, data->FileObject, dosPath, "Create");
}

// Function to handle File Read events
void HandleFileRead(EVENT_RECORD* event) {
    struct FileIo_Read* data = (FileIo_Read*)event->UserData;

    // Find the file path in the map using FileObject
    auto it = fileObjectToPathMap.find(data->FileObject);
    if (it != fileObjectToPathMap.end()) {
        std::wstring filePath = it->second;

        // Log the read event
        WriteToLog(data->IrpPtr, data->FileObject, filePath, "Read", data->Length, data->Offset);
    }
}

// Function to handle File Write events
void HandleFileWrite(EVENT_RECORD* event) {
    struct FileIo_Write* data = (FileIo_Write*)event->UserData;

    // Find the file path in the map using FileObject
    auto it = fileObjectToPathMap.find(data->FileObject);
    if (it != fileObjectToPathMap.end()) {
        std::wstring filePath = it->second;

        // Log the write event
        WriteToLog(data->IrpPtr, data->FileObject, filePath, "Write", data->Length, data->Offset);
    }
}

// Function to handle File Delete events
void HandleFileDelete(EVENT_RECORD* event) {
    struct FileIo_Delete* data = (FileIo_Delete*)event->UserData;

    // Find the file path in the map using FileObject
    auto it = fileObjectToPathMap.find(data->FileObject);
    if (it != fileObjectToPathMap.end()) {
        std::wstring filePath = it->second;

        // Log the delete event
        WriteToLog(data->IrpPtr, data->FileObject, filePath, "Delete");

        // Remove the fileObject from the map
        fileObjectToPathMap.erase(it);
    }
}

// Function to handle File Rename events
void HandleFileRename(EVENT_RECORD* event) {
    struct FileIo_Rename* data = (FileIo_Rename*)event->UserData;

    // Find the old file path in the map using FileObject
    auto it = fileObjectToPathMap.find(data->FileObject);
    if (it != fileObjectToPathMap.end()) {
        std::wstring oldFilePath = it->second;
        std::wstring newFilePath = ConvertNtPathToDosPath(data->NewName);

        // Log the rename event
        WriteToLog(data->IrpPtr, data->FileObject, oldFilePath, "Rename to " + std::string(newFilePath.begin(), newFilePath.end()));

        // Update the map with the new file path
        fileObjectToPathMap[data->FileObject] = newFilePath;
    }
}

// Function to handle File Close events
void HandleFileClose(EVENT_RECORD* event) {
    uint64_t fileObject = ((struct FileIo_Create*)event->UserData)->FileObject;

    // Remove the fileObject from the map
    fileObjectToPathMap.erase(fileObject);
}

// Main event handler for ETW
static void WINAPI TraceEventRecordCallback(EVENT_RECORD* event) {
    DWORD pid = event->EventHeader.ProcessId;
    UCHAR opcode = event->EventHeader.EventDescriptor.Opcode;

    switch (opcode) {
    case PERFINFO_LOG_TYPE_FILE_IO_CREATE:
        HandleFileCreate(event);
        break;
    case PERFINFO_LOG_TYPE_FILE_IO_READ:
        HandleFileRead(event);
        break;
    case PERFINFO_LOG_TYPE_FILE_IO_WRITE:
        HandleFileWrite(event);
        break;
    case PERFINFO_LOG_TYPE_FILE_IO_DELETE:
        HandleFileDelete(event);
        break;
    case PERFINFO_LOG_TYPE_FILE_IO_RENAME:
        HandleFileRename(event);
        break;
    case PERFINFO_LOG_TYPE_FILE_IO_CLOSE:
        HandleFileClose(event);
        break;
    default:
        break;
    }
}

static DWORD WINAPI TraceProcessThread(LPVOID arg)
{
    ProcessTrace(&gTraceHandle, 1, NULL, NULL);
    return 0;
}

static BOOL StartTraceSession()
{
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    EVENT_TRACE_PROPERTIES* p = &gTrace.Properties;

    // stop existing trace, in case it is running
    ZeroMemory(p, sizeof(*p));
    p->Wnode.BufferSize = sizeof(gTrace);
    p->Wnode.Guid = SystemTraceControlGuid;
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->LoggerNameOffset = sizeof(gTrace.Properties);
    ControlTraceW(0, KERNEL_LOGGER_NAMEW, p, EVENT_TRACE_CONTROL_STOP);

    // setup trace properties
    ZeroMemory(p, sizeof(*p));
    p->Wnode.BufferSize = sizeof(gTrace);
    p->Wnode.Guid = SystemTraceControlGuid;
    p->Wnode.ClientContext = 1;
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p->BufferSize = 1024; // 1MiB
    p->MinimumBuffers = 2 * sysinfo.dwNumberOfProcessors;
    p->MaximumBuffers = p->MinimumBuffers + 20;
    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    p->LoggerNameOffset = sizeof(gTrace.Properties);
    p->FlushTimer = 1;
    p->EnableFlags = EVENT_TRACE_FLAG_FILE_IO_INIT;

    // start the trace
    TRACEHANDLE session;
    if (StartTraceW(&session, KERNEL_LOGGER_NAMEW, p) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    EVENT_TRACE_LOGFILEW logfile = {};
    logfile.LoggerName = (LPWSTR)KERNEL_LOGGER_NAMEW;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_REAL_TIME;
    logfile.EventRecordCallback = TraceEventRecordCallback;
    try {
        // open trace for processing
        gTraceHandle = OpenTraceW(&logfile);
        if (gTraceHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            ControlTraceW(0, KERNEL_LOGGER_NAMEW, p, EVENT_TRACE_CONTROL_STOP);
            return FALSE;
        }
    }
    catch (...) {

    }
    // start processing in background thread
    gTraceThread = CreateThread(NULL, 0, TraceProcessThread, NULL, 0, NULL);
    if (gTraceThread == NULL)
    {
        ControlTraceW(0, KERNEL_LOGGER_NAMEW, p, EVENT_TRACE_CONTROL_STOP);
        CloseTrace(gTraceHandle);
        return FALSE;
    }

    return TRUE;
}

static void StopTraceSession(void)
{
    // stop the trace
    ControlTraceW(0, KERNEL_LOGGER_NAMEW, &gTrace.Properties, EVENT_TRACE_CONTROL_STOP);

    // close processing loop, this will wait until all pending buffers are flushed
    // and TraceEventRecordCallback called on all pending events in buffers
    CloseTrace(gTraceHandle);

    // wait for processing thread to finish
    WaitForSingleObject(gTraceThread, INFINITE);
}

int main()
{
    // Read the configuration file before starting the trace
    if (!ReadConfig("config.txt")) {
        return 1; // Exit if configuration fails
    }

    if (!IsElevated())
    {
        fprintf(stderr, "Using ETW with NT kernel logger requires elevated process!\n");
        exit(EXIT_FAILURE);
    }

    if (!EnableProfilePrivilge())
    {
        fprintf(stderr, "Cannot enable profiling privilege for process!\n");
        exit(EXIT_FAILURE);
    }

    if (!StartTraceSession())
    {
        fprintf(stderr, "Cannot start ETW session for NT kernel logger!\n");
        exit(EXIT_FAILURE);
    }
    getchar();

    printf("Stopping...\n");
    StopTraceSession();

    printf("Done!\n");
}