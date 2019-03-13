set(TEST_SOURCES
    ISATest.cc
    BTBPredictorTest.cc
    PipelineBufferTest.cc
    RegisterValueTest.cc
    )

set(SIMENG_SOURCES
    ../../src/A64Architecture.cc
    ../../src/A64Instruction.cc
    ../../src/A64Instruction_address.cc
    ../../src/A64Instruction_decode.cc
    ../../src/A64Instruction_execute.cc
    ../../src/A64InstructionMetadata.cc
    ../../src/BTBPredictor.cc
    ../../src/RegisterFileSet.cc
    ../../src/RegisterValue.cc
    )

include_directories("../../src")
add_executable(unittests ${TEST_SOURCES} ${SIMENG_SOURCES})
target_link_libraries(unittests gtest_main)
target_link_libraries(unittests capstone-static)

add_test(NAME unit_tests COMMAND unittests)
