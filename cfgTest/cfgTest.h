#pragma once

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
	DWORD					dwMustBeZero;
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

typedef BOOL(WINAPI* SETPROCESSVALIDCALLTARGETS)(
	HANDLE					hProcess,
	PVOID					VirtualAddress,
	SIZE_T					RegionSize,
	ULONG					NumberOfOffsets,
	PCFG_CALL_TARGET_INFO	OffsetInformation
	);

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)