add_executable(simeng main.cc)
if (SIMENG_ENABLE_GDB)
  add_subdirectory(gdb)
endif()

# Setting the YAML_OUTPUT macro prints out build metadata and core statistics
# in YAML format at the end of the program.
if( YAML_OUTPUT )
    target_compile_definitions(simeng PRIVATE -DYAML_OUTPUT)
endif()

target_include_directories(simeng PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_link_libraries(simeng libsimeng)

install(TARGETS simeng DESTINATION bin)
