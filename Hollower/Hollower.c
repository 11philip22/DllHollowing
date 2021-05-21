#include <stdio.h>
#include <Windows.h>

int main()
{
	STARTUPINFO			startupInfo;
	PROCESS_INFORMATION processInformation;
	BOOL				bCreateProcessResult;
	DWORD				dwPid = 0;
	HANDLE				hProcessHandle;
	PVOID				pRemoteBuffer = NULL;
	WCHAR				cModuleToInject[] = L"C:\\windows\\system32\\amsi.dll";

	ZeroMemory(&startupInfo, sizeof(startupInfo));
	startupInfo.cb = sizeof(startupInfo);
	ZeroMemory(&processInformation, sizeof(processInformation));

	bCreateProcessResult = CreateProcessA(NULL, "\"explorer.exe\"", NULL, NULL, FALSE,
		DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInformation);
	if (!bCreateProcessResult) 
	{
		printf("[-] CreateProcess failed: (%d).\n", GetLastError());
		goto Cleanup;
	}

	dwPid = processInformation.dwProcessId;
	hProcessHandle = OpenProcess(PROCESS_VM_WRITE, FALSE, dwPid);
	if (!hProcessHandle) 
	{
		printf("[-] Could not get handle to target process: (%d).\n", GetLastError());
		goto Cleanup;
	}

	pRemoteBuffer = VirtualAllocEx(hProcessHandle, NULL, sizeof(cModuleToInject), MEM_COMMIT, PAGE_READWRITE);
	if (!pRemoteBuffer)
	{
		printf("[-] Failed allocating memory in target process: (%d).\n", GetLastError());
		goto Cleanup;
	}

Cleanup:
	CloseHandle(processInformation.hProcess);
	CloseHandle(processInformation.hThread);
}
