
.data
extern h_NtOpenProcessSSN:DWORD
extern h_NtAllocateVirtualMemorySSN:DWORD
extern h_NtWriteVirtualMemorySSN:DWORD
extern h_NtProtectVirtualMemorySSN:DWORD
extern h_NtWaitForSingleObjectSSN:DWORD
extern h_NtFreeVirtualMemorySSN:DWORD
extern h_NtCloseSSN:DWORD
extern h_NtQuerySystemInformationSSN:DWORD
extern h_NtOpenThreadSSN:DWORD
extern h_NtQueueApcThreadSSN:DWORD
extern h_NtResumeThreadSSN:DWORD
extern h_NtCreateUserProcessSSN:DWORD


.code
NtOpenProcess proc 
		mov r10, rcx
		mov eax, h_NtOpenProcessSSN
		syscall                         
		ret                             
NtOpenProcess endp
NtOpenThread proc 
		mov r10, rcx
		mov eax, h_NtOpenThreadSSN
		syscall                         
		ret                             
NtOpenThread endp

NtAllocateVirtualMemory proc    
		mov r10, rcx
		mov eax, h_NtAllocateVirtualMemorySSN      
		syscall                        
		ret                             
NtAllocateVirtualMemory endp
NtWriteVirtualMemory proc 
		mov r10, rcx
		mov eax, h_NtWriteVirtualMemorySSN      
		syscall                        
		ret                             
NtWriteVirtualMemory endp 
NtProtectVirtualMemory proc
		mov r10, rcx
		mov eax, h_NtProtectVirtualMemorySSN       
		syscall
		ret                             
NtProtectVirtualMemory endp



NtWaitForSingleObject proc 
		mov r10, rcx
		mov eax, h_NtWaitForSingleObjectSSN      
		syscall                        
		ret                             
NtWaitForSingleObject endp 
NtFreeVirtualMemory proc
		mov r10, rcx
		mov eax, h_NtFreeVirtualMemorySSN      
		syscall
		ret                             
NtFreeVirtualMemory endp
NtClose proc 
		mov r10, rcx
		mov eax, h_NtCloseSSN      
		syscall                        
		ret
NtClose endp 
NtQuerySystemInformation proc 
		mov r10, rcx
		mov eax, h_NtQuerySystemInformationSSN
		syscall                        
		ret                             
NtQuerySystemInformation endp 

NtResumeThread proc 
		mov r10, rcx
		mov eax, h_NtResumeThreadSSN
		syscall                        
		ret                             
NtResumeThread endp 
NtQueueApcThread proc 
		mov r10, rcx
		mov eax, h_NtQueueApcThreadSSN
		syscall                        
		ret                             
NtQueueApcThread endp 
NtCreateUserProcess proc 
		mov r10, rcx
		mov eax, h_NtCreateUserProcessSSN
		syscall                        
		ret                             
NtCreateUserProcess endp 


end