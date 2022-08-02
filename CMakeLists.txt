cmake_minimum_required(VERSION 3.13)
include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

# FetchContent_MakeAvailable was introduced in 3.14
# there also isn't a version that accepts extra args at the end for add_subdirectory
# hence we write one ourselves
macro(FetchContent_MakeAvailable_Args NAME ARGS)
  FetchContent_GetProperties(${NAME})

  if(NOT ${NAME}_POPULATED)
    FetchContent_Populate(${NAME})
    add_subdirectory(${${NAME}_SOURCE_DIR} ${${NAME}_BINARY_DIR} ${ARGS})
  endif()
endmacro()

# we don't use git for LLVM here as it clones the entire LLVM repo which takes too long and we only need a small part of it
FetchContent_Declare(
  llvm
  URL https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.0/llvm-12.0.0.src.tar.xz
  URL_HASH MD5=ceab21c9081e122a88d82216a80d0dc0
)

# FetchContent_Declare(
# llvm
# URL      https://github.com/llvm/llvm-project/releases/download/llvmorg-9.0.1/llvm-9.0.1.src.tar.xz
# )
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git

  # this versions requires CMake >= 2.8.12 which silences the deprecation warning
  GIT_TAG release-1.11.0
  GIT_PROGRESS TRUE
)

FetchContent_Declare(
  yaml-cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git

  # the latest tagged version (0.6.3) is fairly old and doesn't contain the needed CMake stuff for this to work properly
  # hence we pick the latest working commit
  GIT_TAG a6bbe0e50ac4074f0b9b44188c28cf00caf1a723
  GIT_PROGRESS TRUE
)

FetchContent_Declare(
  capstone-lib
  GIT_REPOSITORY https://github.com/UoB-HPC/capstone.git
  GIT_TAG Armv9.2-update
  GIT_PROGRESS TRUE

  # Old Git tag pre-Armv9.2
  # GIT_TAG e7be7d99e718ef9741026b80fc6f5e100fdf4f94 # trunk
)

cmake_policy(SET CMP0048 NEW)
project(SimEng VERSION 0.9.3 LANGUAGES C CXX)

# If no build type was defined, default to Release
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to Release as none was specified.")
  set(CMAKE_BUILD_TYPE "Release" CACHE
    STRING "Choose the type of build." FORCE)
endif()

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
set(CAPSTONE_INSTALL OFF CACHE BOOL "Disable install of capstone")

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

FetchContent_MakeAvailable_Args(capstone-lib EXCLUDE_FROM_ALL)
include_directories("${capstone_BINARY_DIR}/include" "${capstone_SOURCE_DIR}/include")

# # Setup yaml-cpp ##
set(YAML_CPP_BUILD_TESTS OFF)
set(YAML_CPP_INSTALL OFF)

FetchContent_MakeAvailable_Args(yaml-cpp EXCLUDE_FROM_ALL)

option(SIMENG_ENABLE_TESTS "Whether to enable testing for SimEng" OFF)
option(SIMENG_USE_EXTERNAL_LLVM "Use an external LLVM rather than building it as a submodule" OFF)
option(SIMENG_SANITIZE "Enable compiler sanitizers" OFF)
option(SIMENG_OPTIMIZE "Enable Extra Compiler Optimizatoins" OFF)

if(SIMENG_OPTIMIZE)
  # Turn on link time optimization for all targets.
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)

  check_cxx_compiler_flag(-march=native X86)

  if(X86)
    add_compile_options(-march=native -mtune=native)
    add_link_options(-march=native -mtune=native)
  endif()
endif()

set(SANITIZE_OPTIONS -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -fno-sanitize-recover=address,undefined)

if(SIMENG_SANITIZE)
  add_compile_options(${SANITIZE_OPTIONS})
  add_link_options(${SANITIZE_OPTIONS})
endif()

if(SIMENG_ENABLE_TESTS)
  # # Setup LLVM ##
  if(SIMENG_USE_EXTERNAL_LLVM)
    find_package(LLVM REQUIRED CONFIG NO_CMAKE_BUILDS_PATH)

    # Check LLVM version
    if(${LLVM_PACKAGE_VERSION} VERSION_LESS "8.0")
      message(FATAL_ERROR "LLVM version must be >= 8.0")
    endif()

  else()
    set(LLVM_TARGETS_TO_BUILD "AArch64" CACHE INTERNAL "")

    set(LLVM_BUILD_RUNTIME OFF)

    set(LLVM_BUILD_TOOLS OFF)
    set(LLVM_INCLUDE_TOOLS OFF)

    set(LLVM_BUILD_EXAMPLES OFF)
    set(LLVM_INCLUDE_EXAMPLES OFF)

    set(LLVM_BUILD_TESTS OFF)
    set(LLVM_INCLUDE_TESTS OFF)

    set(LLVM_BUILD_BENCHMARKS OFF)
    set(LLVM_INCLUDE_BENCHMARKS OFF)

    set(LLVM_BUILD_DOCS OFF)
    set(LLVM_INCLUDE_DOCS OFF)

    set(LLVM_INCLUDE_DOCS OFF)
    set(LLVM_ENABLE_BINDINGS OFF)
    set(LLVM_INSTALL_UTILS OFF)

    # XXX all LLVM specific cmake variables must be set BEFORE FetchContent_MakeAvailable otherwise they have no effect
    FetchContent_MakeAvailable_Args(llvm EXCLUDE_FROM_ALL)

    # make sure we get the headers too
    include_directories("${llvm_BINARY_DIR}/include" "${llvm_SOURCE_DIR}/include")

    find_package(LLVM REQUIRED CONFIG NO_DEFAULT_PATH
      PATHS "${llvm_BINARY_DIR}/lib/cmake/llvm")

    # NOTE: we don't do the usual version checks here because it needs vars exported in find_LLVM
    # we just assume it's good beacuse it must be whitelisted in FetchContent_Declare
  endif()

  set(SIMENG_LLVM_VERSION ${LLVM_VERSION_MAJOR} CACHE INTERNAL "LLVM major version number used.")
  message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
  message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

  # Check LLVM was built with the correct targets enabled
  if(NOT "AArch64" IN_LIST LLVM_TARGETS_TO_BUILD)
    message(FATAL_ERROR "LLVM was built without AArch64 target")
  endif()

  # # Setup googletest ##
  FetchContent_MakeAvailable_Args(googletest EXCLUDE_FROM_ALL)
  enable_testing()

  add_subdirectory(test)

  # saves us from having to build all targets before running the tests
  add_custom_target(test-all
    COMMAND ${CMAKE_CTEST_COMMAND}
    DEPENDS unittests regression-aarch64
  )
endif()

# include sources
add_subdirectory(src)
add_subdirectory(docs)
