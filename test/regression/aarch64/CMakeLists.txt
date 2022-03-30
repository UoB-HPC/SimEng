add_executable(regression-aarch64
               AArch64RegressionTest.cc
               AArch64RegressionTest.hh
               Exception.cc
               LoadStoreQueue.cc
               MicroOperation.cc
               SmokeTest.cc
               Syscall.cc
               SystemRegisters.cc
               instructions/arithmetic.cc
               instructions/bitmanip.cc
               instructions/comparison.cc
               instructions/conditional.cc
               instructions/divide.cc
               instructions/float.cc
               instructions/load.cc
               instructions/logical.cc
               instructions/misc.cc
               instructions/multiply.cc
               instructions/neon.cc
               instructions/store.cc
               instructions/sve.cc
               )
target_include_directories(regression-aarch64 PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(regression-aarch64 regression-test-base)

# Define a macro so that tests can find data files
target_compile_definitions(regression-aarch64 PRIVATE
  "SIMENG_AARCH64_TEST_ROOT=\"${CMAKE_CURRENT_SOURCE_DIR}\"")

add_test(NAME regression-aarch64-test COMMAND regression-aarch64)
