#include "ntutils.h"

DWORD64 UtilGetKernelBase() {
	PRTL_PROCESS_MODULES ModuleInformation = NULL;
	NTSTATUS result;
	ULONG SizeNeeded;
	SIZE_T InfoRegionSize;
	DWORD64 output = 0;
	PROTOTYPE_ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation;
	UNICODE_STRING ZWQSIName;

	RtlInitUnicodeString(&ZWQSIName, L"ZwQuerySystemInformation");
	ZwQuerySystemInformation = (PROTOTYPE_ZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&ZWQSIName);

	// get info size
	result = ZwQuerySystemInformation(0x0B, NULL, 0, &SizeNeeded);
	if (result != 0xC0000004) {
		return output;
	}
	InfoRegionSize = SizeNeeded;

	// get info
	while (result == 0xC0000004) {
		InfoRegionSize += 0x1000;
		ModuleInformation = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPoolNx, InfoRegionSize);
		if (ModuleInformation == NULL) {
			return output;
		}

		result = ZwQuerySystemInformation(0x0B, (PVOID)ModuleInformation, (ULONG)InfoRegionSize, &SizeNeeded);
		if (result == 0xC0000004) {
			ExFreePool((PVOID)ModuleInformation);
			ModuleInformation = NULL;
		}
	}

	if (!NT_SUCCESS(result)) {
		return output;
	}

	output = (DWORD64)ModuleInformation->Modules[0].ImageBase;

	// free pool
	ExFreePool((PVOID)ModuleInformation);

	return output;
}

NTSTATUS UtilGetFileSize(LPCWSTR FilePath, HANDLE FileHandle, PSIZE_T FileSize, PDWORD FileSizeHigh) {
	FILE_STANDARD_INFORMATION FileStandard;
	IO_STATUS_BLOCK IoStatusBlock;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING FileNameUnicodeString;
	NTSTATUS result;
	BOOL CloseFileHandle = FALSE;

	if (FileHandle == NULL) {
		if (FilePath == NULL) {
			return (NTSTATUS)0xc0000030; //InvalidParameterMix
		}

		RtlInitUnicodeString(&FileNameUnicodeString, FilePath);

		ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
		ObjectAttributes.RootDirectory = NULL;
		ObjectAttributes.ObjectName = &FileNameUnicodeString;
		ObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_INHERIT;
		ObjectAttributes.SecurityDescriptor = NULL;
		ObjectAttributes.SecurityQualityOfService = NULL;

		// open file
		result = ZwCreateFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		if (!NT_SUCCESS(result)) {
			return result;
		}

		CloseFileHandle = TRUE;
	}

	result = ZwQueryInformationFile(FileHandle, &IoStatusBlock, &FileStandard, sizeof(FILE_STANDARD_INFORMATION), (FILE_INFORMATION_CLASS)5);

	if (CloseFileHandle) ZwClose(FileHandle);

	if (!NT_SUCCESS(result)) {
		if (FileSizeHigh == NULL) {
			*FileSize = -1;
		}
		else {
			*FileSize = 0;
		}
		return result;
	}

	if (FileSizeHigh != NULL)
		*FileSizeHigh = FileStandard.EndOfFile.u.HighPart;

	*FileSize = FileStandard.EndOfFile.u.LowPart;
	return result;
}

NTSTATUS UtilReadFile(LPCWSTR FilePath, PVOID buffer) { // mostly copy-pasty from ReactOS source code
	NTSTATUS result;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	UNICODE_STRING FileNameUnicodeString;
	HANDLE FileHandle;
	SIZE_T FullFileSize;
	LARGE_INTEGER Offset;

	Offset.QuadPart = 0;

	RtlInitUnicodeString(&FileNameUnicodeString, FilePath);

	ObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjectAttributes.RootDirectory = NULL;
	ObjectAttributes.ObjectName = &FileNameUnicodeString;
	ObjectAttributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_INHERIT;
	ObjectAttributes.SecurityDescriptor = NULL;
	ObjectAttributes.SecurityQualityOfService = NULL;

	// open file
	result = ZwCreateFile(&FileHandle, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(result)) {
		return result;
	}

	// get file size file
	result = UtilGetFileSize(NULL, FileHandle, &FullFileSize, NULL);
	if (!NT_SUCCESS(result)) {
		ZwClose(FileHandle);
		return result;
	}

	// read the file
	result = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, buffer, (ULONG)FullFileSize, &Offset, NULL);

	if (result == STATUS_PENDING)
	{
		result = ZwWaitForSingleObject(FileHandle, FALSE, NULL);
		if (NT_SUCCESS(result)) result = IoStatusBlock.Status;
		ZwClose(FileHandle);
		return result;
	}

	ZwClose(FileHandle);
	return result;
}