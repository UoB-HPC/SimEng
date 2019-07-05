add_executable(regression-aarch64
               AArch64RegressionTest.cc
               AArch64RegressionTest.hh
               SmokeTest.cc
               )
target_link_libraries(regression-aarch64 regression-test-base)

add_test(NAME regression-aarch64-test COMMAND regression-aarch64)
