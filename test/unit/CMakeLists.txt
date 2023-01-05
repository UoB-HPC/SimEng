set(TEST_SOURCES
    pipeline/A64FXPortAllocatorTest.cc
    pipeline/BalancedPortAllocatorTest.cc
    pipeline/ExecuteUnitTest.cc
    pipeline/DecodeUnitTest.cc
    pipeline/ExecuteUnitTest.cc
    pipeline/FetchUnitTest.cc
    pipeline/LoadStoreQueueTest.cc
    pipeline/PipelineBufferTest.cc
    pipeline/RegisterAliasTableTest.cc
    pipeline/ReorderBufferTest.cc
    pipeline/WritebackUnitTest.cc
    GenericPredictorTest.cc
    ISATest.cc
    OSTest.cc
    RegisterValueTest.cc
    PoolTest.cc
    ShiftValueTest.cc
    LatencyMemoryInterfaceTest.cc
    SimpleMem.cc
    )

add_executable(unittests ${TEST_SOURCES})

target_include_directories(unittests PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(unittests PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_link_libraries(unittests libsimeng)
target_link_libraries(unittests gmock_main)

add_test(NAME unit_tests COMMAND unittests)
