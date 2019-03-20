set(TEST_SOURCES
    inorder/FetchUnitTest.cc
    inorder/DecodeUnitTest.cc
    inorder/ExecuteUnitTest.cc
    inorder/WritebackUnitTest.cc
    ISATest.cc
    BTBPredictorTest.cc
    PipelineBufferTest.cc
    RegisterValueTest.cc
    )

set(SIMENG_SOURCES
    ../../src/inorder/FetchUnit.cc
    ../../src/inorder/DecodeUnit.cc
    ../../src/inorder/ExecuteUnit.cc
    ../../src/inorder/WritebackUnit.cc
    ../../src/A64Architecture.cc
    ../../src/A64Instruction.cc
    ../../src/A64Instruction_address.cc
    ../../src/A64Instruction_decode.cc
    ../../src/A64Instruction_execute.cc
    ../../src/A64InstructionMetadata.cc
    ../../src/BTBPredictor.cc
    ../../src/Instruction.cc
    ../../src/RegisterFileSet.cc
    ../../src/RegisterValue.cc
    )

include_directories("../../src")

configure_file(${PROJECT_SOURCE_DIR}/external/capstone/arch/AArch64/AArch64GenInstrInfo.inc AArch64GenInstrInfo.inc COPYONLY)

add_executable(unittests ${TEST_SOURCES} ${SIMENG_SOURCES})

target_include_directories(unittests PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(unittests PRIVATE ${PROJECT_SOURCE_DIR}/external/capstone/include)
target_link_libraries(unittests gmock_main)
target_link_libraries(unittests capstone-static)

add_test(NAME unit_tests COMMAND unittests)
