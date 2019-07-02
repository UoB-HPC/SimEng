set(SIMENG_SOURCES
    kernel/Linux.cc
    kernel/LinuxProcess.cc
    models/emulation/Core.cc
    models/inorder/Core.cc
    models/outoforder/Core.cc
    pipeline/BalancedPortAllocator.cc
    pipeline/DecodeUnit.cc
    pipeline/DispatchIssueUnit.cc
    pipeline/ExecuteUnit.cc
    pipeline/FetchUnit.cc
    pipeline/LoadStoreQueue.cc
    pipeline/MappedRegisterFileSet.cc
    pipeline/RegisterAliasTable.cc
    pipeline/RenameUnit.cc
    pipeline/ReorderBuffer.cc
    pipeline/WritebackUnit.cc
    A64Architecture.cc
    A64ExceptionHandler.cc
    A64Instruction.cc
    A64Instruction_address.cc
    A64Instruction_decode.cc
    A64Instruction_execute.cc
    A64InstructionMetadata.cc
    AlwaysNotTakenPredictor.cc
    ArchitecturalRegisterFileSet.cc
    BTBPredictor.cc
    CMakeLists.txt
    Elf.cc
    FlatMemoryInterface.cc
    Instruction.cc
    RegisterFileSet.cc
    RegisterValue.cc
    )

set(SIMENG_HEADERS
    kernel/Linux.hh
    kernel/LinuxProcess.hh
    models/emulation/Core.hh
    models/inorder/Core.hh
    models/outoforder/Core.hh
    pipeline/BalancedPortAllocator.hh
    pipeline/DecodeUnit.hh
    pipeline/DispatchIssueUnit.hh
    pipeline/ExecuteUnit.hh
    pipeline/FetchUnit.hh
    pipeline/LoadStoreQueue.hh
    pipeline/MappedRegisterFileSet.hh
    pipeline/PipelineBuffer.hh
    pipeline/PortAllocator.hh
    pipeline/RegisterAliasTable.hh
    pipeline/RenameUnit.hh
    pipeline/ReorderBuffer.hh
    pipeline/WritebackUnit.hh
    A64Architecture.hh
    A64ExceptionHandler.hh
    A64Instruction.hh
    A64InstructionMetadata.hh
    AlwaysNotTakenPredictor.hh
    ArchitecturalRegisterFileSet.hh
    Architecture.hh
    BranchPredictor.hh
    BTBPredictor.hh
    Core.hh
    Elf.hh
    FlatMemoryInterface.hh
    Instruction.hh
    MemoryInterface.hh
    RegisterValue.hh
    span.hh
    )

configure_file(${PROJECT_SOURCE_DIR}/external/capstone/arch/AArch64/AArch64GenInstrInfo.inc AArch64GenInstrInfo.inc COPYONLY)

add_library(libsimeng SHARED ${SIMENG_SOURCES} ${SIMENG_HEADERS})
set_target_properties(libsimeng PROPERTIES OUTPUT_NAME simeng)

target_include_directories(libsimeng PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(libsimeng PRIVATE ${PROJECT_SOURCE_DIR}/external/capstone/include)
target_link_libraries(libsimeng capstone-static)

set_target_properties(libsimeng PROPERTIES VERSION ${SimEng_VERSION})
set_target_properties(libsimeng PROPERTIES SOVERSION ${SimEng_VERSION_MAJOR})

install(TARGETS libsimeng DESTINATION lib)

# Install headers, preserving directory structure
foreach (file ${SIMENG_HEADERS})
  get_filename_component(dir ${file} DIRECTORY)
  install(FILES ${file} DESTINATION include/simeng/${dir})
endforeach()
