set(SIMENG_SOURCES
    A64Architecture.cc
    A64Architecture.hh
    A64Instruction.cc
    A64Instruction.hh
    A64Instruction_address.cc
    A64Instruction_decode.cc
    A64Instruction_execute.cc
    Architecture.hh
    CMakeLists.txt
    Instruction.hh
    RegisterFile.cc
    RegisterFile.hh
    RegisterValue.cc
    RegisterValue.hh
    main.cc
    )

add_executable(simeng ${SIMENG_SOURCES})
install(TARGETS simeng DESTINATION bin)
