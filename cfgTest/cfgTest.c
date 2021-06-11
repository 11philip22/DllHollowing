#include <stdio.h>
#include <Windows.h>
#include <psapi.h>

#include "cfgTest.h"

BOOL GetMemoryAllocationBaseAndRegionSize(PVOID, PVOID*, PSIZE_T);

INT main() {
	HANDLE						hProcess;
	NTSTATUS					ntStatus = ERROR_SUCCESS;
	STARTUPINFOA				startupInfo;
	PROCESS_INFORMATION			processInformation = { 0 };
	CFG_CALL_TARGET_INFO		cfgCallTargetInfo = { 0 };
	DWORD						dwPid = 0;
	SIZE_T						stRegionSize = NULL;
	PVOID						pvAllocationBase = NULL;
	
	// Function pointers
	SETPROCESSVALIDCALLTARGETS	pSetProcessValidCallTargets = NULL;
	PVOID						pvAddressToAddCfgExceptionTo = NULL;

	//
	// Get address of NtSetContextThread and SetProcessValidCallTargets
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

	CONST HMODULE hKernelbase = LoadLibraryW(L"Kernelbase.dll");
	if (hKernelbase) {
		pSetProcessValidCallTargets = (SETPROCESSVALIDCALLTARGETS)GetProcAddress(hKernelbase, "SetProcessValidCallTargets");
		if (hKernelbase) {
			FreeLibrary(hKernelbase);
		}
	}
	else {
		return ERROR_MOD_NOT_FOUND;
	}

	//
	// Create host process
	//
	//ZeroMemory(&startupInfo, sizeof startupInfo);
	//startupInfo.cb = sizeof startupInfo;
	//ZeroMemory(&processInformation, sizeof processInformation);

	//if (!CreateProcessA(NULL, "\"notepad.exe\"", NULL, NULL, FALSE,
	//	DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInformation)) {
	//	return ERROR_CREATE_FAILED;
	//}

	//dwPid = processInformation.dwProcessId;
	//if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid)) == INVALID_HANDLE_VALUE) {
	//	ntStatus = ERROR_OPEN_FAILED;
	//	goto lblCleanup;
	//}

	// Get memory allocation base and region size by calling VirtualProtect.
	if (GetMemoryAllocationBaseAndRegionSize(pSetProcessValidCallTargets, &pvAllocationBase, &stRegionSize) == FALSE) {
		ntStatus = ERROR_UNHANDLED_ERROR;
		goto lblCleanup;
	}

	//
	// Add cfg exception
	//
	cfgCallTargetInfo.Flags = CFG_CALL_TARGET_VALID;
	cfgCallTargetInfo.Offset = (ULONG_PTR)pSetProcessValidCallTargets - (ULONG_PTR)pvAllocationBase;;
	
	if (pSetProcessValidCallTargets(GetCurrentProcess(), pvAllocationBase, stRegionSize, 1, &cfgCallTargetInfo) == FALSE) {
		printf("%d", GetLastError());
		ntStatus = ERROR_UNHANDLED_ERROR;
		goto lblCleanup;
	}

lblCleanup:
	if (processInformation.hProcess) {
		CloseHandle(processInformation.hProcess);
	}

	if (processInformation.hThread) {
		CloseHandle(processInformation.hThread);
	}

	return ntStatus;
}

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