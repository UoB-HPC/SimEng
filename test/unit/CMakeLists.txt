set(TEST_SOURCES
    aarch64/ArchInfoTest.cc
    aarch64/ArchitectureTest.cc
    aarch64/ExceptionHandlerTest.cc
    aarch64/InstructionTest.cc
    aarch64/ShiftValueTest.cc
    riscv/ArchInfoTest.cc
    riscv/ArchitectureTest.cc
    riscv/ExceptionHandlerTest.cc
    riscv/InstructionTest.cc
    pipeline/A64FXPortAllocatorTest.cc
    pipeline/BalancedPortAllocatorTest.cc
    pipeline/DecodeUnitTest.cc
    pipeline/DispatchIssueUnitTest.cc
    pipeline/ExecuteUnitTest.cc
    pipeline/FetchUnitTest.cc
    pipeline/LoadStoreQueueTest.cc
    pipeline/M1PortAllocatorTest.cc
    pipeline/MappedRegisterFileSetTest.cc
    pipeline/PipelineBufferTest.cc
    pipeline/RegisterAliasTableTest.cc
    pipeline/RenameUnitTest.cc
    pipeline/ReorderBufferTest.cc
    pipeline/WritebackUnitTest.cc
    ArchitecturalRegisterFileSetTest.cc
    ElfTest.cc
    FixedLatencyMemoryInterfaceTest.cc
    FlatMemoryInterfaceTest.cc
    GenericPredictorTest.cc
    OSTest.cc
    PoolTest.cc
    ProcessTest.cc
    RegisterFileSetTest.cc
    RegisterValueTest.cc
    SpecialFileDirGenTest.cc
    )

add_executable(unittests ${TEST_SOURCES})

configure_file(${capstone_SOURCE_DIR}/arch/AArch64/AArch64GenInstrInfo.inc AArch64GenInstrInfo.inc COPYONLY)
configure_file(${capstone_SOURCE_DIR}/arch/RISCV/RISCVGenInstrInfo.inc RISCVGenInstrInfo.inc COPYONLY)

target_include_directories(unittests PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(unittests PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_link_libraries(unittests libsimeng)
target_link_libraries(unittests gmock_main)

add_test(NAME unit_tests COMMAND unittests)
