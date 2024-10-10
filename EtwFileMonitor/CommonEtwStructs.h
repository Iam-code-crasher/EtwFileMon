#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <wchar.h>
#include <stdint.h>

// structures from "C:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\km\wmicore.mof" (in Windows DDK)
typedef struct
{
    uint64_t IrpPtr;
    uint64_t FileObject;
    uint32_t TTID;
    uint32_t CreateOptions;
    uint32_t FileAttributes;
    uint32_t ShareAccess;
    wchar_t OpenPath[1000];
}FILEIO_V3_CREATE, * PFILEIO_V3_CREATE;


typedef struct {
    uintptr_t IrpPtr;
    uintptr_t ThreadId;
    uintptr_t FileObject;
    uint32_t CreateOptions;
    uint32_t FileAttributes;
    uint32_t ShareAccess;
    wchar_t OpenPath[1000];
    // Followed by a variable lenght wchar_t[] filePath;
} FILEIO_V2_CREATE, * PFILEIO_V2_CREATE;



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