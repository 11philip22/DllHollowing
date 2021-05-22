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

	if ((bCreateProcessResult = CreateProcessA(NULL, "\"explorer.exe\"", NULL, NULL, FALSE,
		DETACHED_PROCESS, NULL, NULL, &startupInfo, &processInformation)) == FALSE)
	{
		printf("[-] CreateProcess failed: (%lu).\n", GetLastError());
		goto Cleanup;
	}

	dwPid = processInformation.dwProcessId;
	if ((hProcessHandle = OpenProcess(PROCESS_VM_OPERATION, FALSE, dwPid)) == INVALID_HANDLE_VALUE)
	{
		printf("[-] Could not get handle to target process: (%lu).\n", GetLastError());
		goto Cleanup;
	}

	if ((pRemoteBuffer = VirtualAllocEx(hProcessHandle, NULL, sizeof(cModuleToInject), MEM_COMMIT, PAGE_READWRITE)) == NULL)
	{
		printf("[-] Failed allocating memory in target process: (%lu).\n", GetLastError());
		goto Cleanup;
	}

	if (!WriteProcessMemory(hProcessHandle, pRemoteBuffer, (LPVOID)cModuleToInject, sizeof(cModuleToInject), NULL))
	{

	}

Cleanup:
	CloseHandle(processInformation.hProcess);
	CloseHandle(processInformation.hThread);
}
