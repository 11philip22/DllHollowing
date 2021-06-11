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
	CFG_CALL_TARGET_INFO		cfgCallTargetInfoList[1];
	DWORD						dwPid = 0;
	SIZE_T						stRegionSize = NULL;
	PVOID						pvAllocationBase = NULL;
	
	// Function pointers
	SETPROCESSVALIDCALLTARGETS	pSetProcessValidCallTargets = NULL;
	PVOID						pvAddressToAddCfgExceptionTo = NULL;

	//
	// Get address of SetProcessValidCallTargets
	//
	CONST HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	CONST HMODULE hKernelbase = LoadLibraryW(L"Kernelbase.dll");
	if (hKernelbase && hNtdll) {
		pSetProcessValidCallTargets = (SETPROCESSVALIDCALLTARGETS)GetProcAddress(hKernelbase, "SetProcessValidCallTargets");
		pvAddressToAddCfgExceptionTo = GetProcAddress(hNtdll, "NtSetContextThread");
	}
	else {
		return ERROR_MOD_NOT_FOUND;
	}
	FreeLibrary(hNtdll);
	FreeLibrary(hKernelbase);

	//
	// Create host process
	//
	//ZeroMemory(&startupInfo, sizeof startupInfo);
	//startupInfo.cb = sizeof startupInfo;
	//ZeroMemory(&processInformation, sizeof processInformation);
	//
	//if (!CreateProcessA(NULL, "\"notepad.exe\"", NULL, NULL, FALSE,
	//	DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInformation)) {
	//	return ERROR_CREATE_FAILED;
	//}
	//
	//dwPid = processInformation.dwProcessId;
	//if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, FALSE, dwPid)) == INVALID_HANDLE_VALUE) {
	//	ntStatus = ERROR_OPEN_FAILED;
	//	goto lblCleanup;
	//}

	// Get memory allocation base and region size by calling VirtualProtect.
	if (GetMemoryAllocationBaseAndRegionSize(pvAddressToAddCfgExceptionTo, &pvAllocationBase, &stRegionSize) == FALSE) {
		ntStatus = ERROR_UNHANDLED_ERROR;
		goto lblCleanup;
	}

	//
	// Add cfg exception
	//
	cfgCallTargetInfoList[0].Flags = CFG_CALL_TARGET_VALID;
	cfgCallTargetInfoList[0].Offset = (ULONG_PTR)pvAddressToAddCfgExceptionTo - (ULONG_PTR)pvAllocationBase;;
	
	if (pSetProcessValidCallTargets(GetCurrentProcess(), pvAllocationBase, stRegionSize, 1, cfgCallTargetInfoList) == FALSE) {
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