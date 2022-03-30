set(SIMENG_SOURCES
    arch/aarch64/Architecture.cc
    arch/aarch64/ExceptionHandler.cc
    arch/aarch64/Instruction.cc
    arch/aarch64/Instruction_address.cc
    arch/aarch64/Instruction_decode.cc
    arch/aarch64/Instruction_execute.cc
    arch/aarch64/InstructionMetadata.cc
    arch/aarch64/MicroDecoder.cc
    kernel/Linux.cc
    kernel/LinuxProcess.cc
    models/emulation/Core.cc
    models/inorder/Core.cc
    models/outoforder/Core.cc
    pipeline/A64FXPortAllocator.cc
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
    AlwaysNotTakenPredictor.cc
    ArchitecturalRegisterFileSet.cc
    BTB_BWTPredictor.cc
    BTBPredictor.cc
    CMakeLists.txt
    Elf.cc
    FixedLatencyMemoryInterface.cc
    FlatMemoryInterface.cc
    Instruction.cc
    ModelConfig.cc
    RegisterFileSet.cc
    RegisterValue.cc
    SpecialFileDirGen.cc
    )

configure_file(${capstone_SOURCE_DIR}/arch/AArch64/AArch64GenInstrInfo.inc AArch64GenInstrInfo.inc COPYONLY)

add_library(libsimeng SHARED ${SIMENG_SOURCES} ${SIMENG_HEADERS})
set_target_properties(libsimeng PROPERTIES OUTPUT_NAME simeng)

target_include_directories(libsimeng PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(libsimeng PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(libsimeng capstone-static yaml-cpp)

set_target_properties(libsimeng PROPERTIES VERSION ${SimEng_VERSION})
set_target_properties(libsimeng PROPERTIES SOVERSION ${SimEng_VERSION_MAJOR})

install(TARGETS libsimeng DESTINATION lib)

# Store build metadata in version.hh
get_target_property(SIMENG_COMPILE_OPTIONS libsimeng COMPILE_OPTIONS)
get_target_property(SIMENG_COMPILE_DEFINITIONS libsimeng COMPILE_DEFINITIONS)
get_target_property(SIMENG_VERSION libsimeng VERSION)
configure_file(${PROJECT_SOURCE_DIR}/src/include/simeng/version.hh.in ${PROJECT_SOURCE_DIR}/src/include/simeng/version.hh)