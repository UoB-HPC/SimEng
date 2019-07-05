cmake_minimum_required(VERSION 3.8)
cmake_policy(SET CMP0048 NEW)

project(SimEng VERSION 0.1)

# Require and enable C++17 support, and disable compiler extensions.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Configure RPATH
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
set(CMAKE_MACOSX_RPATH 1)

# Enable PIC for libraries
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Enable additional compiler warnings for all targets
add_compile_options(-Wall)

# capstone
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "Disable Capstone tests")
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Disable Capstone shared library")
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "Disable cstool build")

set(CAPSTONE_ARM_SUPPORT OFF CACHE BOOL "Disable A32 support")
set(CAPSTONE_M68K_SUPPORT OFF CACHE BOOL "Disable M68K support")
set(CAPSTONE_MIPS_SUPPORT OFF CACHE BOOL "Disable MIPS support")
set(CAPSTONE_PPC_SUPPORT OFF CACHE BOOL "Disable PowerPC support")
set(CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "Disable Sparc support")
set(CAPSTONE_SYSZ_SUPPORT OFF CACHE BOOL "Disable SystemZ support")
set(CAPSTONE_XCORE_SUPPORT OFF CACHE BOOL "Disable XCore support")
set(CAPSTONE_X86_SUPPORT OFF CACHE BOOL "Disable x86 support")
set(CAPSTONE_TMS320C64X_SUPPORT OFF CACHE BOOL "Disable TMS320C64x")
set(CAPSTONE_M680X_SUPPORT OFF CACHE BOOL "Disable M680x support")
set(CAPSTONE_EVM_SUPPORT OFF CACHE BOOL "Disable EVM support")
set(CAPSTONE_MOS65XX_SUPPORT OFF CACHE BOOL "Disable MSO65XX support")

add_subdirectory(external/capstone EXCLUDE_FROM_ALL)

# Add LLVM
set(LLVM_TARGETS_TO_BUILD "AArch64" CACHE INTERNAL "")
set(LLVM_BUILD_RUNTIME OFF)
set(LLVM_INCLUDE_TOOLS OFF)
set(LLVM_INCLUDE_EXAMPLES OFF)
set(LLVM_INCLUDE_TESTS OFF)
set(LLVM_INCLUDE_BENCHMARKS OFF)
set(LLVM_INCLUDE_DOCS OFF)
set(LLVM_INCLUDE_UTILS OFF)
add_subdirectory(external/llvm EXCLUDE_FROM_ALL)

add_subdirectory(src)

add_subdirectory(docs)

# googletest
enable_testing()
add_subdirectory(external/googletest EXCLUDE_FROM_ALL)
add_subdirectory(test/unit)
