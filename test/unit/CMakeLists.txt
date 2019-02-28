set(TEST_SOURCES
    ISATest.cc
    PipelineBufferTest.cc
    )

set(SIMENG_SOURCES
    ../../src/A64Architecture.cc
    ../../src/A64Instruction.cc
    ../../src/A64Instruction_address.cc
    ../../src/A64Instruction_decode.cc
    ../../src/A64Instruction_execute.cc
    ../../src/RegisterFileSet.cc
    ../../src/RegisterValue.cc
    )

include_directories("../../src")
add_executable(unittests ${TEST_SOURCES} ${SIMENG_SOURCES})
target_link_libraries(unittests gtest_main)

add_test(NAME unit_tests COMMAND unittests)
