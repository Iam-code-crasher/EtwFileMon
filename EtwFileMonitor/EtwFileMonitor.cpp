// this code will work only when compiled as 64-bit code, and on Windows 10
// older Windows version might require different structure definitions

#define NOMINMAX
#define INITGUID

#include "CommonEtwStructs.h"
#include <iostream>
#include <fstream>
#include <iomanip>  // For formatting

#pragma comment (lib, "shell32.lib")
#pragma comment (lib, "advapi32.lib")

#include <stdio.h>
#include <stdint.h>
#include <thread>
#include <string>
#include <sstream>  // For string stream
#include <map>
#include <string>
#include <algorithm> // for std::transform
#include <cctype>    // for ::tolower or ::towlower (wide characters)
#include <thread>
#include <memory>
#include <Wtsapi32.h>
#pragma comment( lib, "Wtsapi32.lib" )

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


static TRACEHANDLE gTraceHandle;
static DWORD gProcessFilter;

// Global variables for filtering
std::wstring gDirectoryFilter;

// Global flag to stop the trace thread
std::atomic<bool> stopTraceThread(false);
std::thread traceThread;

struct
{
  EVENT_TRACE_PROPERTIES Properties;
  WCHAR SessionName[1024];
}
static gTrace;


std::string GetExecutableDirectory() {
  char buffer[MAX_PATH];
  GetModuleFileNameA(NULL, buffer, MAX_PATH);
  std::string::size_type pos = std::string(buffer).find_last_of("\\/");
  return std::string(buffer).substr(0, pos);
}


// Helper function to write logs with error code details
void WriteDebugLogWithError(const std::string& message, DWORD errorCode) {
  LPVOID errorMsg;
  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, errorCode, 0, (LPSTR)&errorMsg, 0, NULL);
  std::string fullMessage = message + " Error: " + std::to_string(errorCode) + " (" + (LPSTR)errorMsg + ")";
  OutputDebugStringA(fullMessage.c_str());
  LocalFree(errorMsg);  // Free the buffer allocated by FormatMessage
}


// Function to get the process image name (executable name) from a PID
std::string GetProcessImageName(DWORD pid) {
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (hProcess == NULL) {
    std::cerr << "Unable to open process with PID " << pid << ". Error: " << GetLastError() << std::endl;
    return "";
  }

  char imageName[MAX_PATH];
  DWORD size = MAX_PATH;
  if (QueryFullProcessImageNameA(hProcess, 0, imageName, &size)) {
    CloseHandle(hProcess);
    return std::string(imageName);
  }
  else {
    std::cerr << "Unable to retrieve process image name. Error: " << GetLastError() << std::endl;
    CloseHandle(hProcess);
    return "";
  }
}


// Function to read configuration (pid and directory) from a file
bool ReadConfig(const std::string& configFilePath) {
  WriteDebugLogWithError(std::string("Config Path:") + configFilePath, 0);
  std::ifstream configFile(configFilePath);
  if (!configFile.is_open()) {
    //std::cerr << "Error: Could not open configuration file!" << std::endl;
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
    TOKEN_ELEVATION elevation{};
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
      TOKEN_PRIVILEGES tp{};
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

bool IsSameProcess(DWORD pid) {
  // Get the current process ID
  DWORD currentPid = GetCurrentProcessId();

  // Compare the given pid with the current process's pid
  return (pid == currentPid);
}


std::string GetUserFromProcessId(DWORD processId) {
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
  if (hProcess == NULL) {
    std::wcerr << L"Failed to open process with PID: " << processId << L", Error: " << GetLastError() << std::endl;
    return "Unknown";
  }

  HANDLE hToken = NULL;
  if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
    CloseHandle(hProcess);
    std::wcerr << L"Failed to open process token, Error: " << GetLastError() << std::endl;
    return "Unknown";
  }

  // Get token information length first
  DWORD tokenInfoLength = 0;
  GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLength);
  std::unique_ptr<BYTE[]> tokenInfo(new BYTE[tokenInfoLength]);

  // Now get the token information
  if (!GetTokenInformation(hToken, TokenUser, tokenInfo.get(), tokenInfoLength, &tokenInfoLength)) {
    std::wcerr << L"Failed to get token information, Error: " << GetLastError() << std::endl;
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return "Unknown";
  }

  // Extract the SID from the token
  PSID userSid = reinterpret_cast<TOKEN_USER*>(tokenInfo.get())->User.Sid;

  // Convert SID to a human-readable account name
  CHAR accountName[256], domainName[256];
  DWORD accountNameLen = 256, domainNameLen = 256;
  SID_NAME_USE sidType;
  if (!LookupAccountSidA(NULL, userSid, accountName, &accountNameLen, domainName, &domainNameLen, &sidType)) {
    std::wcerr << L"Failed to lookup account SID, Error: " << GetLastError() << std::endl;
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return "Unknown";
  }

  // Close handles
  CloseHandle(hToken);
  CloseHandle(hProcess);

  // Return the domain\username as a wstring
  return std::string(domainName) + "\\" + std::string(accountName);
}

// Function to log events
void WriteToLog(uint32_t pid, uint64_t eventtime, uint64_t FileObject, const std::wstring& filePath, const std::string& operation, uint32_t length = 0, uint64_t offset = 0) {

  //Don't log events from the same process
  if (IsSameProcess(pid)) {
    return;
  }

  std::string logFilePath = GetExecutableDirectory() + "\\EtwFileMonitor.log";
//WriteDebugLogWithError(std::string("Event Log File:") + logFilePath, 0);
  std::ofstream logFile(logFilePath, std::ios_base::app);
  if (!logFile.is_open()) {
    WriteDebugLogWithError("Error: Could not open log file!", GetLastError());
    return;
  }

  logFile << "Event Time : " << eventtime
    << ", Operation: " << operation
    << ", File Path: " << std::string(filePath.begin(), filePath.end())
    << ", PID:" << pid
    << ", User:" << GetUserFromProcessId(pid)
    << ", PPath:" << GetProcessImageName(pid)
    << std::endl;

  logFile.close();
}
// Function to check if a path is a directory
bool IsDirectory(const std::wstring& path) {
  DWORD attributes = GetFileAttributesW(path.c_str());

  if (attributes == INVALID_FILE_ATTRIBUTES) {
    return false; // Path does not exist or there was an error
  }

  // Check if the path is a directory
  return (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

// Function to check if a given path is under the monitored directory
bool isPathMonitored(const std::wstring& path) {
  // Ensure both the path and the directory filter are in the same case (lowercase)
  std::wstring lowerPath = path;
  std::wstring lowerDirectoryFilter = gDirectoryFilter;

  //Check if path is directory, don't monitor it
  if (IsDirectory(path)) {
    return false;
  }

  // Convert both strings to lowercase to ensure case-insensitive comparison
  std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
  std::transform(lowerDirectoryFilter.begin(), lowerDirectoryFilter.end(), lowerDirectoryFilter.begin(), ::towlower);

  // Check if the monitored directory is a prefix of the path
  return lowerPath.find(lowerDirectoryFilter) == 0;
}
// Number of 100-nanosecond intervals between January 1, 1601 and January 1, 1970
#define EPOCH_DIFFERENCE 11644473600LL

// Function to convert FILETIME to Unix Epoch Time (seconds since 1970)
time_t FileTimeToEpoch(const LARGE_INTEGER& fileTime) {
  // Convert the timestamp from 100-nanosecond intervals to seconds
  time_t epochTime = (fileTime.QuadPart / 10000000LL) - EPOCH_DIFFERENCE;
  return epochTime;
}


// Function to handle File Create events
void HandleFileCreate(EVENT_RECORD* event) {
  const UCHAR version = event->EventHeader.EventDescriptor.Version;

  // Lambda function to handle common code for file creation
  auto handleCreateEvent = [&](const auto* data) {
    const std::wstring ntPath(data->OpenPath);
    const std::wstring dosPath = ConvertNtPathToDosPath(ntPath);
    if (!isPathMonitored(dosPath)) {
      return;
    }

    // Use std::unique_ptr if dynamic memory allocation is needed later
    // Example: std::unique_ptr<std::wstring> dosPathPtr = std::make_unique<std::wstring>(dosPath);

    // Store the path in the map using IrpPtr as the key
    fileObjectToPathMap[data->IrpPtr] = dosPath;

    // Log the file creation event
    WriteToLog(event->EventHeader.ProcessId, FileTimeToEpoch(event->EventHeader.TimeStamp), data->FileObject, dosPath, "Create");
    };

  // Handle based on version
  if (version >= 3) {
    const auto* data = static_cast<PFILEIO_V3_CREATE>(event->UserData);
    handleCreateEvent(data);
  }
  else {
    const auto* data = static_cast<PFILEIO_V2_CREATE>(event->UserData);
    handleCreateEvent(data);
  }
}

// Function to handle File Read events
void HandleFileRead(EVENT_RECORD* event) {
  struct FileIo_Read* data = (FileIo_Read*)event->UserData;

  // Find the file path in the map using FileObject
  auto it = fileObjectToPathMap.find(data->FileObject);
  if (it != fileObjectToPathMap.end()) {
    std::wstring filePath = it->second;
    if (!isPathMonitored(filePath)) {
      return;
    }
    // Log the read event
    WriteToLog(event->EventHeader.ProcessId, FileTimeToEpoch(event->EventHeader.TimeStamp), data->FileObject, filePath, "Read", data->Length, data->Offset);
  }
}

// Function to handle File Write events
void HandleFileWrite(EVENT_RECORD* event) {
  struct FileIo_Write* data = (FileIo_Write*)event->UserData;

  // Find the file path in the map using FileObject
  auto it = fileObjectToPathMap.find(data->FileObject);
  if (it != fileObjectToPathMap.end()) {
    std::wstring filePath = it->second;
    if (!isPathMonitored(filePath)) {
      return;
    }
    // Log the write event
    WriteToLog(event->EventHeader.ProcessId, FileTimeToEpoch(event->EventHeader.TimeStamp), data->FileObject, filePath, "Write", data->Length, data->Offset);
  }
}

// Function to handle File Delete events
void HandleFileDelete(EVENT_RECORD* event) {
  struct FileIo_Delete* data = (FileIo_Delete*)event->UserData;

  // Find the file path in the map using FileObject
  auto it = fileObjectToPathMap.find(data->FileObject);
  if (it != fileObjectToPathMap.end()) {
    std::wstring filePath = it->second;
    if (!isPathMonitored(filePath)) {
      return;
    }
    // Log the delete event
    WriteToLog(event->EventHeader.ProcessId, FileTimeToEpoch(event->EventHeader.TimeStamp), data->FileObject, filePath, "Delete");

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
    if (!isPathMonitored(oldFilePath)) {
      return;
    }
    // Log the rename event
    WriteToLog(event->EventHeader.ProcessId, FileTimeToEpoch(event->EventHeader.TimeStamp), data->FileObject, oldFilePath, "Rename to " + std::string(newFilePath.begin(), newFilePath.end()));

    // Update the map with the new file path
    fileObjectToPathMap[data->FileObject] = newFilePath;
  }
}

// Function to handle File Close events
void HandleFileClose(EVENT_RECORD* event) {
  uint64_t fileObject = ((PFILEIO_V3_CREATE)event->UserData)->FileObject;

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

void TraceProcessThread() {
  // Check the stop condition in a loop or rely on ProcessTrace itself being interruptible
  while (!stopTraceThread.load()) {
    ProcessTrace(&gTraceHandle, 1, NULL, NULL);
  }
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
  TraceProcessThread();
  return true;
}

static void StopTraceSession(void)
{
  // Signal the trace thread to stop
  stopTraceThread.store(true);

  // Stop the ETW trace session
  ControlTraceW(0, KERNEL_LOGGER_NAMEW, &gTrace.Properties, EVENT_TRACE_CONTROL_STOP);

  // Wait for the trace thread to finish (join it)
  if (traceThread.joinable()) {
    traceThread.join(); // Wait for the thread to complete
  }

  // Close the trace handle
  CloseTrace(gTraceHandle);
}

int main(int argc, char* argv[]) {
  if (argc > 1) {
    std::string arg = argv[1];

    if (arg == "--start") {
      std::string configPath = GetExecutableDirectory() + "\\config.txt";
      ReadConfig(configPath);

      OutputDebugStringA("starting a new session...");
      if (StartTraceSession()) {
        OutputDebugStringA("Trace session started successfully.");
      }
      else {
        OutputDebugStringA("Failed to start the trace session.");
        return 1;  // Return an error code if the trace session fails to start
      }
    }
    else if (arg == "--stop") {
      OutputDebugStringA("Stopping the trace session...");
      StopTraceSession();
      OutputDebugStringA("Trace session stopped successfully.");
    }
    else {
      OutputDebugStringA("Invalid argument. Use --start to start the trace and --stop to stop it.");
      return 1;
    }
  }
  else {
    OutputDebugStringA("No argument provided. Use --start or --stop.");
    return 1;
  }
  return 0;
}