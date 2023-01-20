; Hell's Gate
; Dynamic system call invocation 
; 
; by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)

.data
	wSystemCall DWORD 000h

.code 
	HellsGate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	HellsGate ENDP

	SysNtOpenProcess PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtOpenProcess ENDP

	SysNtOpenProcessToken PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtOpenProcessToken ENDP

	SysNtClose PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtClose ENDP

	SysNtCreateFile PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtCreateFile ENDP

	SysNtWriteFile PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtWriteFile ENDP

	SysNtWaitForSingleObject PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	SysNtWaitForSingleObject ENDP

	GetHeap PROC
		mov rax, qword ptr GS:[60h]
		mov rax, qword ptr [rax+30h]
		ret
	GetHeap ENDP

	CurrentProcess PROC
		mov rax, qword ptr 0FFFFFFFFFFFFFFFFh
		ret
	CurrentProcess ENDP 

end