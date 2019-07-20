add_executable(regression-aarch64
               AArch64RegressionTest.cc
               AArch64RegressionTest.hh
               SmokeTest.cc
               instructions/arithmetic.cc
               instructions/comparison.cc
               instructions/divide.cc
               instructions/load.cc
               instructions/multiply.cc
               instructions/store.cc
               )
target_include_directories(regression-aarch64 PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(regression-aarch64 regression-test-base)

add_test(NAME regression-aarch64-test COMMAND regression-aarch64)
