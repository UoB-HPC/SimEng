set(TEST_SOURCES
    ISATest.cc
    )

set(SIMENG_SOURCES
    ../src/A64Architecture.cc
    ../src/A64Instruction.cc
    ../src/A64Instruction_address.cc
    ../src/A64Instruction_decode.cc
    ../src/A64Instruction_execute.cc
    ../src/RegisterFile.cc
    ../src/RegisterValue.cc
    )

include_directories("../src")
add_executable(test ${TEST_SOURCES} ${SIMENG_SOURCES})
target_link_libraries(test gtest_main)

add_test(NAME all_tests COMMAND test)
