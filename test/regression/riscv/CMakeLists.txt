add_executable(regression-riscv
            RISCVRegressionTest.cc
            RISCVRegressionTest.hh
            Exception.cc
            LoadStoreQueue.cc
            SmokeTest.cc
            instructions/arithmetic.cc
            instructions/load.cc
            instructions/store.cc
               )
target_include_directories(regression-riscv PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(regression-riscv regression-test-base)

# Define a macro so that tests can find data files
target_compile_definitions(regression-riscv PRIVATE
  "SIMENG_RISCV_TEST_ROOT=\"${CMAKE_CURRENT_SOURCE_DIR}\"")

add_test(NAME regression-riscv-test COMMAND regression-riscv)
