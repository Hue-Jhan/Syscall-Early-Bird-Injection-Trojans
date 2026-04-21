
.data
extern h_NtOpenProcessSSN:DWORD
extern h_NtOpenProcessSyscall:QWORD
extern h_NtAllocateVirtualMemorySSN:DWORD
extern h_NtAllocateVirtualMemorySyscall:QWORD
extern h_NtWriteVirtualMemorySSN:DWORD
extern h_NtWriteVirtualMemorySyscall:QWORD
extern h_NtProtectVirtualMemorySSN:DWORD
extern h_NtProtectVirtualMemorySyscall:QWORD
extern h_NtWaitForSingleObjectSSN:DWORD
extern h_NtWaitForSingleObjectSyscall:QWORD
extern h_NtFreeVirtualMemorySSN:DWORD
extern h_NtFreeVirtualMemorySyscall:QWORD
extern h_NtCloseSSN:DWORD
extern h_NtCloseSyscall:QWORD
extern h_NtQuerySystemInformationSSN:DWORD
extern h_NtQuerySystemInformationSyscall:QWORD
extern h_NtOpenThreadSSN:DWORD
extern h_NtOpenThreadSyscall:QWORD
extern h_NtQueueApcThreadSSN:DWORD
extern h_NtQueueApcThreadSyscall:QWORD
extern h_NtResumeThreadSSN:DWORD
extern h_NtResumeThreadSyscall:QWORD
extern h_NtCreateUserProcessSSN:DWORD
extern h_NtCreateUserProcessSyscall:QWORD


.code

NtOpenProcess proc 
		mov r10, rcx
		mov eax, h_NtOpenProcessSSN
		jmp qword ptr h_NtOpenProcessSyscall                         
		ret                             
NtOpenProcess endp
NtOpenThread proc 
		mov r10, rcx
		mov eax, h_NtOpenThreadSSN
		jmp qword ptr h_NtOpenThreadSyscall
		ret                             
NtOpenThread endp

NtAllocateVirtualMemory proc    
		mov r10, rcx
		mov eax, h_NtAllocateVirtualMemorySSN      
		jmp qword ptr h_NtAllocateVirtualMemorySyscall          
		ret                             
NtAllocateVirtualMemory endp
NtWriteVirtualMemory proc 
		mov r10, rcx
		mov eax, h_NtWriteVirtualMemorySSN      
		jmp qword ptr h_NtWriteVirtualMemorySyscall                       
		ret                             
NtWriteVirtualMemory endp 
NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, h_NtProtectVirtualMemorySSN       
		jmp qword ptr h_NtProtectVirtualMemorySyscall
		ret                             
NtProtectVirtualMemory endp



NtWaitForSingleObject proc 
		mov r10, rcx
		mov eax, h_NtWaitForSingleObjectSSN      
		jmp qword ptr h_NtWaitForSingleObjectSyscall                       
		ret                             
NtWaitForSingleObject endp
NtFreeVirtualMemory proc
		mov r10, rcx
		mov eax, h_NtFreeVirtualMemorySSN      
		jmp qword ptr h_NtFreeVirtualMemorySyscall
		ret                             
NtFreeVirtualMemory endp
NtClose proc 
		mov r10, rcx
		mov eax, h_NtCloseSSN      
		jmp qword ptr h_NtCloseSyscall                        
		ret
NtClose endp 

NtQuerySystemInformation proc 
		mov r10, rcx
		mov eax, h_NtQuerySystemInformationSSN
		jmp qword ptr h_NtQuerySystemInformationSyscall                       
		ret                             
NtQuerySystemInformation endp 

NtQueueApcThread proc 
		mov r10, rcx
		mov eax, h_NtQueueApcThreadSSN
		jmp qword ptr h_NtQueueApcThreadSyscall
		ret                             
NtQueueApcThread endp
NtResumeThread proc 
		mov r10, rcx
		mov eax, h_NtResumeThreadSSN
		jmp qword ptr h_NtResumeThreadSyscall                     
		ret                             
NtResumeThread endp 
NtCreateUserProcess proc 
		mov r10, rcx
		mov eax, h_NtCreateUserProcessSSN
		jmp qword ptr h_NtCreateUserProcessSyscall                     
		ret                             
NtCreateUserProcess endp 


end