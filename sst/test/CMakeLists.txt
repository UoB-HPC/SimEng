set(SIMENG_SST_TEST_SOURCES 
    main.cc
    src/tg0_llvm_assemble.cc
    src/tg1_load_store.cc
    src/tg2_cache_access.cc
    src/tg3_request_split.cc
    src/tg4_request_misaligned.cc
)
add_executable(sstsimengtest ${SIMENG_SST_TEST_SOURCES})

add_compile_options(-Wall)

set(SSTCONFIGDIR ${CMAKE_CURRENT_SOURCE_DIR}/sstconfigs)
if(SST_TEST_CMD)
target_compile_definitions(sstsimengtest PUBLIC SST_INSTALL_DIR="${SST_INSTALL_DIR}" SST_TEST_CMD="${SST_TEST_CMD}" SST_CONFIG_DIR="${SSTCONFIGDIR}")
else()
target_compile_definitions(sstsimengtest PUBLIC SST_INSTALL_DIR="${SST_INSTALL_DIR}" SST_CONFIG_DIR="${SSTCONFIGDIR}")
endif()

target_include_directories(libsimeng PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(sstsimengtest PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_test(NAME simeng_sst_tests COMMAND sstsimengtest)
