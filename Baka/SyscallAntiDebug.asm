_DATA SEGMENT
syscall_number DQ 0
address_ntapi DQ 0
_DATA ENDS

.code





SetAddressNtApi proc
        mov [address_ntapi], rcx
        ret
SetAddressNtApi endp

SetSyscallCallNumber proc
        mov [syscall_number], rcx
        ret
SetSyscallCallNumber endp


CallSyscall proc

		mov r10, rcx
		mov eax, dword ptr[syscall_number]
		jmp qword ptr [address_ntapi ] ; jmp to syscall and we don't need ret

CallSyscall endp


end 