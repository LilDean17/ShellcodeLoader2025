.DATA

    align 8
g_SysConfig dq 0         ; 8 字节，全局变量，初始为 0

.CODE



SysSetConfig PROC
        mov qword ptr [g_SysConfig], rcx
        
        mov rcx, [rsp+ 8]              ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]

        RET
SysSetConfig ENDP



AsmNtAllocateVirtualMemory PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtAllocateVirtualMemory ENDP

AsmNtCreateThreadEx PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtCreateThreadEx ENDP

AsmNtClose PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtClose ENDP

AsmNtSignalAndWaitForSingleObject PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtSignalAndWaitForSingleObject ENDP

AsmNtReadVirtualMemory PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtReadVirtualMemory ENDP


AsmNtOpenThread PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtOpenThread ENDP

AsmNtOpenProcess PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtOpenProcess ENDP


AsmNtWaitForSingleObject PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtWaitForSingleObject ENDP

AsmNtWriteVirtualMemory PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtWriteVirtualMemory ENDP


AsmNtFreeVirtualMemory PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtFreeVirtualMemory ENDP

AsmNtProtectVirtualMemory PROC
        mov r10, rcx
        mov r11, qword ptr [g_SysConfig]                ; 取出全局指针
        
        mov eax, [r11 + 8h]                             ; syscall number
        jmp qword ptr[r11]                              ; syscall 函数地址
AsmNtProtectVirtualMemory ENDP

END
