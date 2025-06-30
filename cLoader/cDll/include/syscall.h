#include "peb.h"
#include "define.h"

#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth
                                                                
#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | \
                                   0xFFFF)


typedef struct _SW2_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
} SW2_SYSCALL_ENTRY, * PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, * PSW2_SYSCALL_LIST;

typedef struct _SYS_CONFIG {
    PVOID Adr; 
    WORD  Ssn; 
} SYS_CONFIG, * PSYS_CONFIG;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;


extern "C" VOID SaveRegisters(void);

extern "C" VOID GetSourceRsp(DWORD64 SourceRsp);

extern "C" VOID GetStackPtr(DWORD64 stack);

extern "C" VOID StoreStack(void);

extern "C" VOID RecoverStack(void);

extern "C" VOID SaveStack(DWORD64*);

extern "C" VOID RestoreStack(DWORD64*);

extern "C" VOID SysSetConfig(
    IN PSYS_CONFIG Config
);

extern "C" NTSTATUS SysInvoke(
    _Inout_ /* Args... */
);



BOOL PopulateSyscallList();

EXTERN_C DWORD GetSyscallNumber(DWORD FunctionHash);

EXTERN_C unsigned long long GetRandomSyscallAddress(void);



NTSTATUS SysNtOpenThread(
    OUT    PHANDLE            ThreadHandle,         // RCX
    IN     ACCESS_MASK        DesiredAccess,        // RDX
    IN     POBJECT_ATTRIBUTES ObjectAttributes,     // R8
    IN     PCLIENT_ID         ClientId              // R9
    
);

NTSTATUS NTAPI SysNtOpenProcess(
    OUT    PHANDLE             ProcessHandle,
    IN     ACCESS_MASK         DesiredAccess,
    IN     POBJECT_ATTRIBUTES  ObjectAttributes,
    IN     PCLIENT_ID          ClientId              
    
);

NTSTATUS NTAPI SysNtWaitForSingleObject(
    IN     HANDLE         Handle,
    IN     BOOLEAN        Alertable,
    IN     PLARGE_INTEGER Timeout             
    
);

NTSTATUS NTAPI SysNtAllocateVirtualMemory(
    IN     HANDLE    ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    IN     ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T   RegionSize,
    IN     ULONG     AllocationType,
    IN     ULONG     Protect
    
);

NTSTATUS NTAPI SysNtWriteVirtualMemory(
    IN       HANDLE  ProcessHandle,
    IN       PNTSTATUS   BaseAddress,
    IN CONST VOID* Buffer,
    IN       SIZE_T  BufferSize,
    OUT      PSIZE_T NumberOfBytesWritten              
    
);


NTSTATUS NTAPI SysNtFreeVirtualMemory(
    IN     HANDLE  ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    IN     ULONG   FreeType             
    
);

NTSTATUS NTAPI SysNtProtectVirtualMemory(
    IN     HANDLE  ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    IN     ULONG   NewProtect,
    OUT    PULONG  OldProtect             
    
);

NTSTATUS NTAPI SysNtReadVirtualMemory(
    IN      HANDLE  ProcessHandle,
    IN      PVOID   BaseAddress,
    OUT     PVOID   Buffer,
    IN      SIZE_T  BufferSize,
    OUT     PSIZE_T NumberOfBytesRead            
    
);

NTSTATUS NTAPI SysNtSignalAndWaitForSingleObject(
    IN     HANDLE         SignalHandle,
    IN     HANDLE         WaitHandle,
    IN     BOOLEAN        Alertable,
    IN     PLARGE_INTEGER Timeout            
    
);

NTSTATUS NTAPI SysNtClose(
    IN HANDLE Handle            
);

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
);

extern "C" NTSTATUS NTAPI AsmNtAllocateVirtualMemory(
    IN     HANDLE    ProcessHandle,         // RCX
    _Inout_ PVOID* BaseAddress,             // RDX
    IN     ULONG_PTR ZeroBits,              // R8
    _Inout_ PSIZE_T   RegionSize,           // R9
    IN     ULONG     AllocationType,        // rsp+28h
    IN     ULONG     Protect                // rsp+20h
);


extern "C" NTSTATUS NTAPI AsmNtCreateThreadEx(
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
);


extern "C" NTSTATUS NTAPI AsmNtClose(
    IN HANDLE Handle
);

extern "C" NTSTATUS NTAPI AsmNtSignalAndWaitForSingleObject(
    IN     HANDLE         SignalHandle,
    IN     HANDLE         WaitHandle,
    IN     BOOLEAN        Alertable,
    IN     PLARGE_INTEGER Timeout

);

extern "C" NTSTATUS NTAPI AsmNtReadVirtualMemory(
    IN      HANDLE  ProcessHandle,
    IN      PVOID   BaseAddress,
    OUT     PVOID   Buffer,
    IN      SIZE_T  BufferSize,
    OUT     PSIZE_T NumberOfBytesRead

);





extern "C" NTSTATUS AsmNtOpenThread(
    OUT    PHANDLE            ThreadHandle,         // RCX
    IN     ACCESS_MASK        DesiredAccess,        // RDX
    IN     POBJECT_ATTRIBUTES ObjectAttributes,     // R8
    IN     PCLIENT_ID         ClientId              // R9

);

extern "C" NTSTATUS NTAPI AsmNtOpenProcess(
    OUT    PHANDLE             ProcessHandle,
    IN     ACCESS_MASK         DesiredAccess,
    IN     POBJECT_ATTRIBUTES  ObjectAttributes,
    IN     PCLIENT_ID          ClientId

);

extern "C" NTSTATUS NTAPI AsmNtWaitForSingleObject(
    IN     HANDLE         Handle,
    IN     BOOLEAN        Alertable,
    IN     PLARGE_INTEGER Timeout

);

extern "C" NTSTATUS NTAPI AsmNtWriteVirtualMemory(
    IN       HANDLE  ProcessHandle,
    IN       PVOID   BaseAddress,
    IN CONST VOID* Buffer,
    IN       SIZE_T  BufferSize,
    OUT      PSIZE_T NumberOfBytesWritten

);


extern "C" NTSTATUS NTAPI AsmNtFreeVirtualMemory(
    IN     HANDLE  ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    IN     ULONG   FreeType

);

extern "C" NTSTATUS NTAPI AsmNtProtectVirtualMemory(
    IN     HANDLE  ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    IN     ULONG   NewProtect,
    OUT    PULONG  OldProtect

);