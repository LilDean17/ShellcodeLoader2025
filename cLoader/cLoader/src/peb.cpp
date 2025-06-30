#include "peb.h"
#include "define.h"

extern "C" int* GetPeb();

FARPROC  _GET_PROC_ADDRESS(HANDLE handle, ULONG funchash)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)handle;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD64)pDos + pDos->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + (DWORD64)pDos);
	DWORD* Name = (DWORD*)((DWORD64)pDos + pExportDirectory->AddressOfNames);
	WORD* NameOrdinals = (WORD*)((DWORD64)pDos + (DWORD64)pExportDirectory->AddressOfNameOrdinals);
	DWORD* Functions = (DWORD*)((DWORD64)pDos + (DWORD64)pExportDirectory->AddressOfFunctions);
	DWORD i = 0;
	for (; i < pExportDirectory->NumberOfNames; i++)
	{
		CONST WCHAR* FuncName = (CONST WCHAR*) (*(DWORD*)(Name + i) + (DWORD64)pDos);
		if (HashEx((PVOID)FuncName,_WCSLEN(FuncName),1, FUNC_HASH) == funchash)
		{
			DWORD index = *(WORD*)(NameOrdinals + i);
			DWORD Rva = Functions[index];
			DWORD64* abAddr = (DWORD64*)((DWORD64)pDos + Rva);
			return (FARPROC)abAddr;
		}
	}
	return NULL;
}

HMODULE _GET_MODULE_HANDLE(ULONG dll_hash)
{
	PPEB pPeb;
	PPEB_LDR_DATA pLdr;
	PLDR_DATA_TABLE_ENTRY pDataTable;
	pPeb = (PPEB)GetPeb();
	pLdr = pPeb->Ldr;
	
	pDataTable = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;
	while (pDataTable->DllBase != NULL)
	{
		if (HashEx(pDataTable->FullDllName.Buffer, 1, 1, FUNC_HASH) == dll_hash)			// 自实现获取长度函数
		{
			return (HMODULE)pDataTable->InInitializationOrderLinks.Flink;
		}
		pDataTable = (PLDR_DATA_TABLE_ENTRY)pDataTable->InLoadOrderLinks.Flink;
	}
	return NULL;
}

ULONG HashEx(PVOID String, BOOL isWstring, BOOL  Upper, ULONG Hash)
{
	WCHAR* Ptr = (WCHAR*)String;
	CHAR* ptr = (CHAR*)String;
	ULONG Length = 0;
	if (isWstring == TRUE)
	{
		Length = _WCSLEN((CONST WCHAR*)String) * 2;
		if (!String)	// 如果字符串不存在
		{
			return 0;
		}
		do {
			UCHAR character = *Ptr;			// 取出当前遍历到的字母

			if (!Length)					// 如果长度不存在，且ptr也不存在就退出
			{
				if (!*Ptr) {
					break;
				}
			}
			else {							// 如果当前字母已经不存在00，退出循环
				if ((ULONG)((DWORD64)(Ptr)-(DWORD64)String) >= Length) {
					break;
				}
				if (!*Ptr) {				// 如果ptr不存在就++
					++Ptr;
				}
			}
			if (Upper) {
				if (character >= 'a') {
					character -= 0x20;
				}
			}
			Hash = ((Hash << 5) + Hash) + character;
			++Ptr;
		} while (TRUE);

		return Hash;
	}
	else
	{
		Length = _STRLEN((CONST CHAR*)String);
		if (!String)	// 如果字符串不存在
		{
			return 0;
		}
		do {
			UCHAR character = *ptr;			// 取出当前遍历到的字母

			if (!Length)					// 如果长度不存在，且ptr也不存在就退出
			{
				if (!*ptr) {
					break;
				}
			}
			else {							// 如果当前字母已经不存在00，退出循环
				if ((ULONG)((DWORD64)(ptr)-(DWORD64)String) >= Length) {
					break;
				}
				if (!*ptr) {				// 如果ptr不存在就++
					++ptr;
				}
			}
			if (Upper) {
				if (character >= 'a') {
					character -= 0x20;
				}
			}
			Hash = ((Hash << 5) + Hash) + character;
			++ptr;
		} while (TRUE);
		return Hash;
	}
	
}

DWORD _WCSLEN(CONST WCHAR* buf)
{
	DWORD len = 0;
	while (buf[len] != 0x00)
	{
		len++;
	}
	return len;
}

DWORD _STRLEN(CONST CHAR* buf)
{
	DWORD len = 0;
	while (buf[len] != 0x00)
	{
		len++;
	}
	return len;
}

ULONG Random(ULONG max)
{
	ULONG Seed = 0;
	pRtlRandomEx RtlRandomEx = (pRtlRandomEx)_GET_PROC_ADDRESS(_GET_MODULE_HANDLE(_Ntdll), _RtlRandom);
	Seed = RtlRandomEx(&Seed) % (max + 1);
	
	return Seed;
}



