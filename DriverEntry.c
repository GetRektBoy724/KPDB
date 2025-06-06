#include "DriverEntry.h"

LPCSTR WantedSymbolList[] = { 
	"PspLoadImageNotifyRoutine", 
	"PspCreateProcessNotifyRoutine", 
	"PspCreateThreadNotifyRoutine", 
	"CallbackListHead",
	"EtwThreatIntProvRegHandle", 
	"KiServiceTable", 
	"KiTimerDispatch" };

SYMBOL_DATA SymbolsData[MAX_SYMBOL_DATA + 1];

void KpdbDemoRoutine() {
	for (int i = 0; i < (sizeof(WantedSymbolList) / sizeof(LPCSTR)); i++) {
		SymbolsData[i].SymbolName = WantedSymbolList[i];
	}

	SIZE_T FileSize = 0;
	PVOID pdbfile = NULL;
	LPCWSTR pdbfilepath = L"\\??\\C:\\mysymbol\\ntkrnlmp.pdb"; // replace this with the path of the PDB (keep the "\\??\\")
	// read PDB file and parse
	DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - Reading NT symbols...");
	{
		// get file size
		if (!NT_SUCCESS(UtilGetFileSize(pdbfilepath, NULL, &FileSize, NULL))) {
			DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - UtilGetFileSize failed!");
			return;
		}

		// allocate memory for file
		pdbfile = ExAllocatePool(PagedPool, FileSize);

		// read file
		if (!NT_SUCCESS(UtilReadFile(pdbfilepath, pdbfile)))
		{
			ExFreePool(pdbfile);
			DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - UtilReadFile failed!");
			return;
		}

		// run the parse
		if (!KpdbGetPDBSymbolOffset(pdbfile, SymbolsData)) {
			// free pool
			ExFreePool(pdbfile);
			DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - KpdbGetPDBSymbolOffset failed!");
			return;
		}

		//if (!KpdbTravelTPICodeView(pdbfile)) {
		//	// free pool
		//	ExFreePool(pdbfile);
		//	DbgPrintEx(0, 0, "[KPDB] KpdbDemoRoutine - KpdbTravelTPICodeView failed!\n");
		//	return;
		//}

		LONG offset = KpdbGetStructMemberOffset(pdbfile, "_EPROCESS", "UniqueProcessId");
		if (offset != -1) {
			DbgPrintEx(0, 0, "[KPDB] Offset of _EPROCESS->UniqueProcessId: %d\n", offset);
		}
		else {
			DbgPrintEx(0, 0, "[KPDB] Failed to get offset for _EPROCESS->UniqueProcessId.\n");
		}

		// free pool
		ExFreePool(pdbfile);
	}

	KpdbConvertSecOffsetToRVA(UtilGetKernelBase(), SymbolsData); // kernel base = ntoskrnl module base

	DWORD Iterator = 0;
	while (SymbolsData[Iterator].SectionOffset) {
		DbgPrintEx(0, 0, "[KPDB] Symbol %s = 0x%p", SymbolsData[Iterator].SymbolName, SymbolsData[Iterator].SymbolRVA + UtilGetKernelBase());
		Iterator++;
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	KpdbDemoRoutine();

	return STATUS_UNSUCCESSFUL;
}