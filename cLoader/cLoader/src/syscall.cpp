#include "syscall.h"
#include "peb.h"
SYS_CONFIG SysConfig = { 0 };
DWORD64 Stack[10] = { 0 };
SW2_SYSCALL_LIST SW2_SyscallList = { 0, 1 };


BOOL PopulateSyscallList(void)
{
	if (SW2_SyscallList.Count) return TRUE;

	HMODULE hNtDllBase = _GET_MODULE_HANDLE(_Ntdll);
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)hNtDllBase;
    PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, hNtDllBase, DosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
    DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, hNtDllBase, VirtualAddress);
    // 遍历内存中 ntdll 的导出表，获取 Zw 开头的函数名称，存储到全局数组 SW2_SyscallList.Entries
    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW2_RVA2VA(PDWORD, hNtDllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, hNtDllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, hNtDllBase, ExportDirectory->AddressOfNameOrdinals);

    // 使用未排序的Zw*填充SW2_SyscallList
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, hNtDllBase, Names[NumberOfNames - 1]);

        // 判断函数名开头是否为Zw
        if (*(USHORT*)FunctionName == 'wZ')
        {
            // 计算Hash值，存入Entries
            Entries[i].Hash = HashEx(FunctionName,0 , 1, FUNC_HASH);
            // 保存函数地址，存入Entries
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

            i++;
            // 如果达到最大条目数,结束循环
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // 保存找到的syscall总数到SW2_SyscallList
    SW2_SyscallList.Count = i;

    // 按地址升序对列表进行排序
    // 遍历SW2_SyscallList.Count - 1次
    for (i = 0; i < SW2_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW2_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // 交换syscall条目,TempEntry用于临时存储
                SW2_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;

}

EXTERN_C DWORD GetSyscallNumber(DWORD FunctionHash)
{
    //确保SW2_SyscallList已被填充
    if (!PopulateSyscallList()) return -1;
    // 遍历SW2_SyscallList.Count次
    for (DWORD i = 0; i < SW2_SyscallList.Count; i++)
    {
        // 如果传入的FunctionHash与SW2_SyscallList.Entries[i]的Hash相等，则为调用号
        if (FunctionHash == SW2_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

// 随机选择一个syscall地址并返回
//#ifdef RANDSYSCALL
#ifdef _WIN64
EXTERN_C unsigned long long GetRandomSyscallAddress(void)
#else
EXTERN_C DWORD SW2_GetRandomSyscallAddress(int callType)
#endif
{
    // syscall指令和Nt函数的距离
    int instructOffset = 0;
    // syscall指令的第一个字节的值
    int instructValue = 0;
#ifndef _WIN64
    unsigned int ntdllBase = 0;
    // 如果是32位程序在64位系统上运行(WOW64)
    if (callType == 0)
    {
        instructOffset = 0x05;// 距离为0x05
        instructValue = 0x0E8;// 第一字节值为0xE8
    }
    // 如果是32位程序在32位系统上运行 
    else if (callType == 1)
    {
        instructOffset = 0x05;// 距离为0x05
        instructValue = 0x0BA;// 第一字节值为0xBA
    }
#else   // 这里是直接系统调用，默认距离为0x12的地方是syscall地址。而间接系统调用是匹配syscall硬编码0x0F05来获取syscall地址
        // 需要的话修改这里实现间接syscall。
    unsigned long long ntdllBase = (unsigned long long)_GET_MODULE_HANDLE(_Ntdll);
    // 如果是64位程序在64位系统上运行
    instructOffset = 0x12;// 距离为0x12
    instructValue = 0x0F;// 第一字节值为0x0F
#endif
    // 循环随机选择syscall
    do
    {
        // 随机索引
        int randNum = Random(SW2_SyscallList.Count + 1);
        // 判断随机选择的syscall的第一字节是否符合预期
        if (*(unsigned char*)(ntdllBase + SW2_SyscallList.Entries[randNum].Address + instructOffset) == instructValue)
            // 返回syscall地址
            return (ntdllBase + SW2_SyscallList.Entries[randNum].Address + instructOffset);
    } while (1);
}


NTSTATUS NTAPI SysNtOpenThread(
    OUT    PHANDLE            ThreadHandle,         // RCX
    IN     ACCESS_MASK        DesiredAccess,        // RDX
    IN     POBJECT_ATTRIBUTES ObjectAttributes,     // R8
    IN     PCLIENT_ID         ClientId             // R9,             
    
)
{
    NTSTATUS   NtStatus = STATUS_SUCCESS;
    SysConfig.Adr = (PVOID)GetRandomSyscallAddress();
    SysConfig.Ssn = GetSyscallNumber(_SysZwOpenThread);
    SysSetConfig(&SysConfig);
    NtStatus = AsmNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);

    if (NtStatus != STATUS_SUCCESS)
    {
        return NtStatus;
    }
    return STATUS_SUCCESS;
}



NTSTATUS NTAPI SysNtWaitForSingleObject(
    IN     HANDLE         Handle,
    IN     BOOLEAN        Alertable,
    IN     PLARGE_INTEGER Timeout
    
) {
    NTSTATUS   NtStatus = STATUS_SUCCESS;
    SysConfig.Adr = (PVOID)GetRandomSyscallAddress();
    SysConfig.Ssn = GetSyscallNumber(_SysZwWaitForSingleObject);
    SysSetConfig(&SysConfig);
    NtStatus = AsmNtWaitForSingleObject(Handle, Alertable, Timeout);

    if (NtStatus != STATUS_SUCCESS)
    {
        return NtStatus;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SysNtAllocateVirtualMemory(
    IN     HANDLE    ProcessHandle,         // RCX
    _Inout_ PVOID* BaseAddress,             // RDX
    IN     ULONG_PTR ZeroBits,              // R8
    _Inout_ PSIZE_T   RegionSize,           // R9
    IN     ULONG     AllocationType,        // rsp+28h
    IN     ULONG     Protect                // rsp+20h
) {
    NTSTATUS   NtStatus = STATUS_SUCCESS;
    SysConfig.Adr = (PVOID)GetRandomSyscallAddress();
    SysConfig.Ssn = GetSyscallNumber(_SysZwAllocateVirtualMemory);
    SysSetConfig(&SysConfig);
    NtStatus = AsmNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    if (NtStatus != STATUS_SUCCESS)
    {
        return NtStatus;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SysNtWriteVirtualMemory(
    IN       HANDLE  ProcessHandle,
    IN       PVOID   BaseAddress,
    IN CONST VOID* Buffer,
    IN       SIZE_T  BufferSize,
    OUT      PSIZE_T NumberOfBytesWritten
    
) {
    NTSTATUS   NtStatus = STATUS_SUCCESS;
    SysConfig.Adr = (PVOID)GetRandomSyscallAddress();
    SysConfig.Ssn = GetSyscallNumber(_SysZwWriteVirtualMemory);
    SysSetConfig(&SysConfig);
    NtStatus = AsmNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
    if (NtStatus != STATUS_SUCCESS)
    {
        return NtStatus;
    }
    return STATUS_SUCCESS;
}


NTSTATUS NTAPI SysNtFreeVirtualMemory(
    IN     HANDLE  ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    IN     ULONG   FreeType
    
) {
    NTSTATUS   NtStatus = STATUS_SUCCESS;
    SysConfig.Adr = (PVOID)GetRandomSyscallAddress();
    SysConfig.Ssn = GetSyscallNumber(_SysZwFreeVirtualMemory);
    SysSetConfig(&SysConfig);
    NtStatus = AsmNtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
    if (NtStatus != STATUS_SUCCESS)
    {
        return NtStatus;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SysNtProtectVirtualMemory(
    IN     HANDLE  ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    IN     ULONG   NewProtect,
    OUT    PULONG  OldProtect
    
) {
    NTSTATUS   NtStatus = STATUS_SUCCESS;
    SysConfig.Adr = (PVOID)GetRandomSyscallAddress();
    SysConfig.Ssn = GetSyscallNumber(_SysZwProtectVirtualMemory);
    SysSetConfig(&SysConfig);
    NtStatus = AsmNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);

    if (NtStatus != STATUS_SUCCESS)
    {
        return NtStatus;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SysNtReadVirtualMemory(
    IN      HANDLE  ProcessHandle,
    IN      PVOID   BaseAddress,
    OUT     PVOID   Buffer,
    IN      SIZE_T  BufferSize,
    OUT     PSIZE_T NumberOfBytesRead
    
) {
    NTSTATUS   NtStatus = STATUS_SUCCESS;
    SysConfig.Adr = (PVOID)GetRandomSyscallAddress();
    SysConfig.Ssn = GetSyscallNumber(_SysZwReadVirtualMemory);
    SysSetConfig(&SysConfig);
    NtStatus = AsmNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);

    if (NtStatus != STATUS_SUCCESS)
    {
        return NtStatus;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SysNtSignalAndWaitForSingleObject(
    IN     HANDLE         SignalHandle,
    IN     HANDLE         WaitHandle,
    IN     BOOLEAN        Alertable,
    IN     PLARGE_INTEGER Timeout
    
) {
    NTSTATUS   NtStatus = STATUS_SUCCESS;
    SysConfig.Adr = (PVOID)GetRandomSyscallAddress();
    SysConfig.Ssn = GetSyscallNumber(_SysZwSignalAndWaitForSingleObject);
    SysSetConfig(&SysConfig);
    NtStatus = AsmNtSignalAndWaitForSingleObject(SignalHandle, WaitHandle, Alertable, Timeout);

    if (NtStatus != STATUS_SUCCESS)
    {
        return NtStatus;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SysNtClose(
    IN HANDLE Handle
) {
    NTSTATUS   NtStatus = STATUS_SUCCESS;
    SysConfig.Adr = (PVOID)GetRandomSyscallAddress();
    SysConfig.Ssn = GetSyscallNumber(_SysZwClose);
    SysSetConfig(&SysConfig);
    NtStatus = AsmNtClose(Handle);

    if (NtStatus != STATUS_SUCCESS)
    {
        return NtStatus;
    }
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SysNtCreateThreadEx(
    OUT PHANDLE     hThread,
    IN  ACCESS_MASK DesiredAccess,
    IN  PVOID       ObjectAttributes,
    IN  HANDLE      ProcessHandle,
    IN  PVOID       lpStartAddress,
    IN  PVOID       lpParameter,
    IN  ULONG       Flags,
    IN  SIZE_T      StackZeroBits,
    IN  SIZE_T      SizeOfStackCommit,
    IN  SIZE_T      SizeOfStackReserve,
    IN  PVOID       lpBytesBuffer
    
) {
    NTSTATUS   NtStatus = STATUS_SUCCESS;
    SysConfig.Adr = (PVOID)GetRandomSyscallAddress();
    SysConfig.Ssn = GetSyscallNumber(_SysZwCreateThreadEx);
    SysSetConfig(&SysConfig);
    NtStatus = AsmNtCreateThreadEx(hThread, DesiredAccess, ObjectAttributes, ProcessHandle, lpStartAddress, lpParameter, Flags, StackZeroBits, SizeOfStackCommit, SizeOfStackReserve, lpBytesBuffer);
    if (NtStatus != STATUS_SUCCESS)
    {
        return NtStatus;
    }
    return STATUS_SUCCESS;
}
