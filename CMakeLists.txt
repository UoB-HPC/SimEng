cmake_minimum_required(VERSION 3.13)
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

# Disable RTTI for all targets
add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)

# Include SimEng API headers in all targets and install them
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/include)
install(DIRECTORY src/include/simeng
        DESTINATION include
        FILES_MATCHING PATTERN "*.hh")

# capstone
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "Disable Capstone tests")
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Disable Capstone shared library")
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "Disable cstool build")

set(CAPSTONE_ARM_SUPPORT OFF CACHE BOOL "Disable A32 support")
set(CAPSTONE_MIPS_SUPPORT OFF CACHE BOOL "Disable MIPS support")
set(CAPSTONE_X86_SUPPORT OFF CACHE BOOL "Disable x86 support")
set(CAPSTONE_PPC_SUPPORT OFF CACHE BOOL "Disable PowerPC support")
set(CAPSTONE_SPARC_SUPPORT OFF CACHE BOOL "Disable Sparc support")
set(CAPSTONE_SYSZ_SUPPORT OFF CACHE BOOL "Disable SystemZ support")
set(CAPSTONE_XCORE_SUPPORT OFF CACHE BOOL "Disable XCore support")
set(CAPSTONE_M68K_SUPPORT OFF CACHE BOOL "Disable M68K support")
set(CAPSTONE_TMS320C64X_SUPPORT OFF CACHE BOOL "Disable TMS320C64x")
set(CAPSTONE_M680X_SUPPORT OFF CACHE BOOL "Disable M680x support")
set(CAPSTONE_EVM_SUPPORT OFF CACHE BOOL "Disable EVM support")
set(CAPSTONE_MOS65XX_SUPPORT OFF CACHE BOOL "Disable MSO65XX support")
set(CAPSTONE_WASM_SUPPORT OFF CACHE BOOL "Disable WASM support")
set(CAPSTONE_BPF_SUPPORT OFF CACHE BOOL "Disable BPF support")
set(CAPSTONE_RISCV_SUPPORT OFF CACHE BOOL "Disable RISCV support")

add_subdirectory(external/capstone EXCLUDE_FROM_ALL)

# Add LLVM
option(SIMENG_USE_EXTERNAL_LLVM
       "Use an external LLVM rather than building it as a submodule")
if (SIMENG_USE_EXTERNAL_LLVM)
  find_package(LLVM REQUIRED CONFIG NO_CMAKE_BUILDS_PATH)
else()
  set(LLVM_TARGETS_TO_BUILD "AArch64" CACHE INTERNAL "")
  set(LLVM_BUILD_RUNTIME OFF)
  set(LLVM_INCLUDE_TOOLS OFF)
  set(LLVM_INCLUDE_EXAMPLES OFF)
  set(LLVM_INCLUDE_TESTS OFF)
  set(LLVM_INCLUDE_BENCHMARKS OFF)
  set(LLVM_INCLUDE_DOCS OFF)
  set(LLVM_INCLUDE_UTILS OFF)
  add_subdirectory(external/llvm EXCLUDE_FROM_ALL)
  find_package(LLVM REQUIRED CONFIG NO_DEFAULT_PATH
               PATHS "${PROJECT_BINARY_DIR}/external/llvm/lib/cmake/llvm")
endif()
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# Check LLVM version
if (${LLVM_PACKAGE_VERSION} VERSION_LESS "8.0")
  message(FATAL_ERROR "LLVM version must be >= 8.0")
endif()

# Check LLVM was built with the correct targets enabled
if (NOT "AArch64" IN_LIST LLVM_TARGETS_TO_BUILD)
  message(FATAL_ERROR "LLVM was built without AArch64 target")
endif()

add_subdirectory(src)

add_subdirectory(docs)

# googletest
enable_testing()
add_subdirectory(external/googletest EXCLUDE_FROM_ALL)
add_subdirectory(test)

# yaml-cpp
add_subdirectory(external/yaml-cpp EXCLUDE_FROM_ALL)