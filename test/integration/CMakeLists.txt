set(TEST_SOURCES
    ConfigTest.cc
    VirtMemTests.cc
    ../testenv/FilesEnv.cc
    )

add_executable(integrationtests ${TEST_SOURCES})

target_include_directories(integrationtests PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(integrationtests PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_link_libraries(integrationtests libsimeng)
target_link_libraries(integrationtests gmock_main)

add_test(NAME integration_tests COMMAND integrationtests)
