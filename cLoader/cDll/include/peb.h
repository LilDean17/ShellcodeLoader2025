#pragma once
#include<Windows.h>

#define MAX_WOW64_SHARED_ENTRIES 16
#define PROCESSOR_FEATURE_MAX 64

typedef enum ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign,                 // None == 0 == standard design
    NEC98x86,                       // NEC PC98xx series on X86
    EndAlternatives                 // past end of known alternatives
} MY_ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} MY_KSYSTEM_TIME, * MY_PKSYSTEM_TIME;


typedef struct KUSER_SHARED_DATA
{
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;

    volatile MY_KSYSTEM_TIME InterruptTime;
    volatile MY_KSYSTEM_TIME SystemTime;
    volatile MY_KSYSTEM_TIME TimeZoneBias;

    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;

    WCHAR NtSystemRoot[260];

    ULONG MaxStackTraceDepth;

    ULONG CryptoExponent;

    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG Reserved2[7];

    ULONG NtProductType;
    BOOLEAN ProductTypeIsValid;

    ULONG NtMajorVersion;
    ULONG NtMinorVersion;

    BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];

    ULONG Reserved1;
    ULONG Reserved3;

    volatile ULONG TimeSlip;

    MY_ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;

    LARGE_INTEGER SystemExpirationDate;

    ULONG SuiteMask;

    BOOLEAN KdDebuggerEnabled;

    UCHAR NXSupportPolicy;

    volatile ULONG ActiveConsoleId;

    volatile ULONG DismountCount;

    ULONG ComPlusPackage;

    ULONG LastSystemRITEventTickCount;

    ULONG NumberOfPhysicalPages;

    BOOLEAN SafeBootMode;
    union
    {
        UCHAR TscQpcData;
        struct
        {
            UCHAR TscQpcEnabled : 1;
            UCHAR TscQpcSpareFlag : 1;
            UCHAR TscQpcShift : 6;
        };
    };
    UCHAR TscQpcPad[2];

    union
    {
        ULONG TraceLogging;
        ULONG SharedDataFlags;
        struct
        {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgSystemDllRelocated : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgSEHValidationEnabled : 1;
            ULONG SpareBits : 25;
        };
    };
    ULONG DataFlagsPad[1];

    ULONGLONG TestRetInstruction;
    ULONG SystemCall;
    ULONG SystemCallReturn;
    ULONGLONG SystemCallPad[3];

    union
    {
        volatile MY_KSYSTEM_TIME TickCount;
        volatile ULONG64 TickCountQuad;
        struct
        {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        };
    };

    ULONG Cookie;

    // Entries below all invalid below Windows Vista

    ULONG CookiePad[1];

    LONGLONG ConsoleSessionForegroundProcessId;

    ULONG Wow64SharedInformation[MAX_WOW64_SHARED_ENTRIES];

    USHORT UserModeGlobalLogger[16];
    ULONG ImageFileExecutionOptions;

    ULONG LangGenerationCount;

    union
    {
        ULONGLONG AffinityPad; // only valid on Windows Vista
        ULONG_PTR ActiveProcessorAffinity; // only valid on Windows Vista
        ULONGLONG Reserved5;
    };
    volatile ULONG64 InterruptTimeBias;
    volatile ULONG64 TscQpcBias;

    volatile ULONG ActiveProcessorCount;
    volatile USHORT ActiveGroupCount;
    USHORT Reserved4;

    volatile ULONG AitSamplingValue;
    volatile ULONG AppCompatFlag;

    ULONGLONG SystemDllNativeRelocation;
    ULONG SystemDllWowRelocation;

    ULONG XStatePad[1];
    XSTATE_CONFIGURATION XState;
} MY_KUSER_SHARED_DATA, * MY_PKUSER_SHARED_DATA;


#define MY_SHARED_USER_DATA_VA 0x7FFE0000
#define USER_SHARED_DATA ((MY_KUSER_SHARED_DATA * const)MY_SHARED_USER_DATA_VA)




typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;  
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef struct _LDR_DATA_TABLE_ENTRY
{

    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    ULONG TimeDateStamp;

} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA
{
    ULONG                   Length;
    BOOLEAN                 Initialized;
    PVOID                   SsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
}PEB, * PPEB;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    PVOID Handle;
}CURDIR, * PCURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
}RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB2 {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBase;
    PPEB_LDR_DATA           LoaderData;
    PRTL_USER_PROCESS_PARAMETERS                   ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    PVOID                   FastPebLockRoutine;
    PVOID                   FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    PVOID                   FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    BYTE                    Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PVOID** ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    BYTE                    TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
} PEB2, * PPEB2;

typedef struct _SLEEP_PARAM
{
    UINT32  TimeOut;
    PVOID   Master;
    PVOID   Slave;
} SLEEP_PARAM, * PSLEEP_PARAM;

HMODULE _GET_MODULE_HANDLE(ULONG dll_hash);

ULONG HashEx(PVOID String, BOOL isWstring, BOOL  Upper, ULONG hash);

DWORD _WCSLEN(CONST WCHAR* buf);

DWORD _STRLEN(CONST CHAR* buf);

FARPROC  _GET_PROC_ADDRESS(HANDLE handle, ULONG funchash);

ULONG Random(ULONG max);

__forceinline ULONG NtGetTickCount() { return (ULONG)((USER_SHARED_DATA->TickCountQuad * USER_SHARED_DATA->TickCountMultiplier) >> 24); }


typedef
ULONG
(NTAPI
    * pRtlRandomEx)(
        PULONG Seed
        );

typedef
RPC_STATUS
(NTAPI
    * puuidFromStringA)(
        RPC_CSTR StringUuid,
        UUID* Uuid
        );


typedef
RPC_STATUS
(NTAPI
    * pNtCreateThreadEx)(
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


typedef
RPC_STATUS
(NTAPI
    * pLdrLoadDll)(
        IN OPTIONAL PWSTR DllPath,
        IN OPTIONAL PULONG DllCharacteristics,
        IN PUNICODE_STRING DllName,
        OUT PVOID* DllHandle
        );

typedef
BOOL
(WINAPI
    * pFreeLibrary)(
        _In_ HMODULE hLibModule
        );
typedef
NTSTATUS
(NTAPI
    * pRtlIpv4StringToAddressA)(
        _In_ PCSTR S,
        _In_ BOOLEAN Strict,
        _Out_ PCSTR* Terminator,
        _Out_ struct in_addr* Addr
        );

typedef VOID(NTAPI LDR_ENUM_CALLBACK)(_In_ PLDR_DATA_TABLE_ENTRY ModuleInformation, _In_ PVOID Parameter, _Out_ BOOLEAN* Stop);
typedef LDR_ENUM_CALLBACK* PLDR_ENUM_CALLBACK;

typedef 
NTSTATUS
(NTAPI
    * pLdrEnumerateLoadedModules)(
    BOOL                   ReservedFlag,
    LDR_ENUM_CALLBACK     EnumProc,
    PVOID                  context
    );

typedef 
NTSTATUS
(NTAPI
    * pEnumUILanguagesW)(
UILANGUAGE_ENUMPROCW lpUILanguageEnumProc,
  DWORD                dwFlags,
  LONG_PTR             lParam
    );

typedef 
NTSTATUS
(NTAPI
    * pEnumCalendarInfoExA)(
  CALINFO_ENUMPROCEXA lpCalInfoEnumProcEx,
  LCID                Locale,
  CALID               Calendar,
  CALTYPE             CalType
);


typedef 
LPVOID
(NTAPI
    * pConvertThreadToFiber)(
        _In_opt_ LPVOID lpParameter
    );
typedef 
LPVOID
(NTAPI
    * pCreateFiber)(
        _In_     SIZE_T dwStackSize,
        _In_     LPFIBER_START_ROUTINE lpStartAddress,
        _In_opt_ LPVOID lpParameter
    );
typedef 
VOID
(NTAPI
    * pSwitchToFiber)(
        _In_ LPVOID lpFiber
    );

typedef 
BOOL
(WINAPI
    * pFreeConsole)(
        VOID
    );

