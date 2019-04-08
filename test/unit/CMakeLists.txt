set(TEST_SOURCES
    inorder/DecodeUnitTest.cc
    outoforder/BalancedPortAllocatorTest.cc
    outoforder/LoadStoreQueueTest.cc
    outoforder/RegisterAliasTableTest.cc
    outoforder/ReorderBufferTest.cc
    pipeline/FetchUnitTest.cc
    pipeline/WritebackUnitTest.cc
    pipeline/ExecuteUnitTest.cc
    ISATest.cc
    BTBPredictorTest.cc
    PipelineBufferTest.cc
    RegisterValueTest.cc
    )

set(SIMENG_SOURCES
    ../../src/inorder/DecodeUnit.cc
    ../../src/outoforder/BalancedPortAllocator.cc
    ../../src/outoforder/RegisterAliasTable.cc
    ../../src/outoforder/ReorderBuffer.cc
    ../../src/outoforder/LoadStoreQueue.cc
    ../../src/pipeline/ExecuteUnit.cc
    ../../src/pipeline/FetchUnit.cc
    ../../src/pipeline/WritebackUnit.cc
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
