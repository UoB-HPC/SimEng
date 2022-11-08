set(SIMENG_SST_TEST_SOURCES 
    main.cc
    test_files/tg0_llvm_assemble.cc
    test_files/tg1_load_store.cc
    test_files/tg2_cache_access.cc
    test_files/tg3_request_split.cc
    test_files/tg4_request_misaligned.cc
)
add_executable(sstsimengtest ${SIMENG_SST_TEST_SOURCES})

add_compile_options(-Wall)

set(SSTTESTDIR ${CMAKE_CURRENT_SOURCE_DIR})
if(SST_TEST_CMD)

target_compile_definitions(
 sstsimengtest PUBLIC 
 SST_INSTALL_DIR="${SST_INSTALL_DIR}"
 SST_TEST_CMD="${SST_TEST_CMD}"
 SST_TEST_DIR="${SSTTESTDIR}"
 SST_TESTS_MODEL_CONFIG_PATH="${SST_TESTS_MODEL_CONFIG_PATH}"
 )

else()
target_compile_definitions(
 sstsimengtest PUBLIC 
 SST_INSTALL_DIR="${SST_INSTALL_DIR}"
 SST_TEST_DIR="${SSTTESTDIR}"
 SST_TESTS_MODEL_CONFIG_PATH="${SST_TESTS_MODEL_CONFIG_PATH}"
 )
endif()

target_include_directories(libsimeng PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(sstsimengtest PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_test(NAME simeng_sst_tests COMMAND sstsimengtest)
