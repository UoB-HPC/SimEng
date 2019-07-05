# Add object library for base regression test fixture class
add_library(regression-test-base OBJECT RegressionTest.cc RegressionTest.hh)

# Include and link to libsimeng
target_include_directories(regression-test-base
                           PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_link_libraries(regression-test-base libsimeng)

# Link to gtest
target_link_libraries(regression-test-base gtest_main)

# Include LLVM
target_include_directories(regression-test-base PRIVATE
                           ${PROJECT_SOURCE_DIR}/external/llvm/include
                           ${PROJECT_BINARY_DIR}/external/llvm/include)

# Link to LLVM
# List of LLVM libraries obtained from running:
#   llvm-config --libs aarch64asmparser object
target_link_libraries(regression-test-base
                      LLVMAArch64AsmParser
                      LLVMAArch64Desc
                      LLVMAArch64Utils
                      LLVMAArch64Info
                      LLVMObject
                      LLVMMCParser
                      LLVMMC
                      LLVMDebugInfoCodeView
                      LLVMDebugInfoMSF
                      LLVMBitReader
                      LLVMCore
                      LLVMRemarks
                      LLVMBinaryFormat
                      LLVMSupport
                      LLVMDemangle
                      )

# Add regression test directories for each architecture
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_subdirectory(aarch64)
