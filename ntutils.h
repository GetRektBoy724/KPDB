#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <minwindef.h>
#include <intrin.h>
#include <ntddndis.h>
#include <strsafe.h>
#include <fltkernel.h>

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	ULONG Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef NTSTATUS(NTAPI* PROTOTYPE_ZWQUERYSYSTEMINFORMATION)(DWORD info, PVOID infoinout, ULONG len, PULONG retLen);

DWORD64 UtilGetKernelBase();
NTSTATUS UtilGetFileSize(LPCWSTR FilePath, HANDLE FileHandle, PSIZE_T FileSize, PDWORD FileSizeHigh);
NTSTATUS UtilReadFile(LPCWSTR FilePath, PVOID buffer);