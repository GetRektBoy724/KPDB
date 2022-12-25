#pragma once
#include "kpdb.h"
#include "ntutils.h"

#define MAX_SYMBOL_DATA 32

void KpdbDemoRoutine();
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
