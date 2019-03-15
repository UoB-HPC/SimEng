cmake_minimum_required(VERSION 3.8)
project(SimEng)

# Require and enable C++17 support, and disable compiler extensions.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable additional compiler warnings for all targets
add_compile_options(-Wall)

# capstone
set(CAPSTONE_BUILD_TESTS OFF)
set(CAPSTONE_BUILD_SHARED OFF)
set(CAPSTONE_BUILD_CSTOOL OFF)

set(CAPSTONE_ARM_SUPPORT OFF)
set(CAPSTONE_M68K_SUPPORT OFF)
set(CAPSTONE_MIPS_SUPPORT OFF)
set(CAPSTONE_PPC_SUPPORT OFF)
set(CAPSTONE_SPARC_SUPPORT OFF)
set(CAPSTONE_SYSZ_SUPPORT OFF)
set(CAPSTONE_XCORE_SUPPORT OFF)
set(CAPSTONE_X86_SUPPORT OFF)
set(CAPSTONE_TMS320C64X_SUPPORT OFF)
set(CAPSTONE_M680X_SUPPORT OFF)
set(CAPSTONE_EVM_SUPPORT OFF)
set(CAPSTONE_MOS65XX_SUPPORT OFF)

add_subdirectory(external/capstone)
include_directories(external/capstone/include)

add_subdirectory(src)

add_subdirectory(docs)

# googletest
enable_testing()
add_subdirectory(external/googletest EXCLUDE_FROM_ALL)
add_subdirectory(test/unit)
