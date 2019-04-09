set(SIMENG_SOURCES
    inorder/Core.cc
    inorder/Core.hh
    outoforder/BalancedPortAllocator.cc
    outoforder/BalancedPortAllocator.hh
    outoforder/Core.cc
    outoforder/Core.hh
    outoforder/DispatchIssueUnit.cc
    outoforder/DispatchIssueUnit.hh
    outoforder/PortAllocator.hh
    pipeline/DecodeUnit.cc
    pipeline/DecodeUnit.hh
    pipeline/ExecuteUnit.cc
    pipeline/ExecuteUnit.hh
    pipeline/FetchUnit.cc
    pipeline/FetchUnit.hh
    pipeline/LoadStoreQueue.cc
    pipeline/LoadStoreQueue.hh
    pipeline/RegisterAliasTable.cc
    pipeline/RegisterAliasTable.hh
    pipeline/RenameUnit.cc
    pipeline/RenameUnit.hh
    pipeline/ReorderBuffer.cc
    pipeline/ReorderBuffer.hh
    pipeline/WritebackUnit.cc
    pipeline/WritebackUnit.hh
    emulation/Core.cc
    emulation/Core.hh
    A64Architecture.cc
    A64Architecture.hh
    A64Instruction.cc
    A64Instruction.hh
    A64Instruction_address.cc
    A64Instruction_decode.cc
    A64Instruction_execute.cc
    A64InstructionMetadata.cc
    A64InstructionMetadata.hh
    AlwaysNotTakenPredictor.cc
    AlwaysNotTakenPredictor.hh
    Architecture.hh
    BranchPredictor.hh
    BTBPredictor.cc
    BTBPredictor.hh
    Core.hh
    CMakeLists.txt
    Elf.cc
    Elf.hh
    Instruction.cc
    Instruction.hh
    PipelineBuffer.hh
    RegisterFileSet.cc
    RegisterFileSet.hh
    RegisterValue.cc
    RegisterValue.hh
    span.hh
    main.cc
    )

configure_file(${PROJECT_SOURCE_DIR}/external/capstone/arch/AArch64/AArch64GenInstrInfo.inc AArch64GenInstrInfo.inc COPYONLY)

add_executable(simeng ${SIMENG_SOURCES})

target_include_directories(simeng PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(simeng PRIVATE ${PROJECT_SOURCE_DIR}/external/capstone/include)
target_link_libraries(simeng capstone-static)

install(TARGETS simeng DESTINATION bin)
