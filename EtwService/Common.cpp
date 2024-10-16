#include "Common.h"

std::wstring GetExecutableDirectory() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
    return std::wstring(buffer).substr(0, pos);
}

// Helper function to write logs with error code details
void WriteDebugLogWithError(const std::wstring& message, DWORD errorCode) {
    LPVOID errorMsg;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorCode, 0, (LPWSTR)&errorMsg, 0, NULL);
    std::wstring fullMessage = message + L" Error: " + std::to_wstring(errorCode) + L" (" + (LPWSTR)errorMsg + L")";
    OutputDebugStringW(fullMessage.c_str());
    LocalFree(errorMsg);  // Free the buffer allocated by FormatMessage
}

