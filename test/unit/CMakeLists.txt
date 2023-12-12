set(TEST_SOURCES
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
    ArchitectureTest.cc
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

target_include_directories(unittests PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(unittests PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_link_libraries(unittests libsimeng)
target_link_libraries(unittests gmock_main)

add_test(NAME unit_tests COMMAND unittests)
