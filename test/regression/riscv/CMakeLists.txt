add_executable(regression-riscv
            RISCVRegressionTest.cc
            RISCVRegressionTest.hh
            Exception.cc
            LoadStoreQueue.cc
            InorderPipeline.cc
            SmokeTest.cc
            Syscall.cc
            instructions/arithmetic.cc
            instructions/multiplyDivide.cc
            instructions/load.cc
            instructions/store.cc
            instructions/jump.cc
            instructions/branch.cc
            instructions/atomic.cc
            instructions/float.cc
            instructions/compressed.cc
        )

configure_file(${capstone_SOURCE_DIR}/arch/RISCV/RISCVGenInstrInfo.inc RISCVGenInstrInfo.inc COPYONLY)

target_include_directories(regression-riscv PRIVATE
                            ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(regression-riscv PRIVATE
                            ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(regression-riscv regression-test-base)
target_compile_options(regression-riscv PRIVATE -Wall -pedantic -Werror)

# Define a macro so that tests can find data files
target_compile_definitions(regression-riscv PRIVATE
  "SIMENG_RISCV_TEST_ROOT=\"${CMAKE_CURRENT_SOURCE_DIR}\"")

add_test(NAME regression-riscv-test COMMAND regression-riscv)

#add_custom_command(
#        TARGET regression-riscv
#        POST_BUILD
#        COMMAND ${CMAKE_COMMAND} -E copy ${PROJECT_SOURCE_DIR}/SimEngDefaultProgram ${CMAKE_CURRENT_BINARY_DIR}/SimEngDefaultProgram
#)
