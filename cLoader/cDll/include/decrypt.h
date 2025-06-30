#include <Windows.h>
#include "peb.h"


DWORD64 UuidsLen(CONST CHAR(*uuids)[0x08]);

LPVOID UuidDecode(CONST CHAR(*uuids)[0x08], OUT PDWORD64 len, puuidFromStringA uuidFromStringA);

PVOID Ipv4Decode(CONST CHAR(*ipv4)[0x08], OUT PDWORD64 len, pRtlIpv4StringToAddressA myRtlIpv4StringToAddressA);

DWORD64 Ipv4Len(CONST CHAR(*ipv4)[0x08]);

PVOID aesDecrypt(const CHAR* keys, DWORD sizeofkeys, const CHAR* iv, PVOID buf, DWORD64 sizeofbuf, DWORD64 sizeofout);
