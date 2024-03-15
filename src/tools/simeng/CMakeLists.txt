add_executable(simeng main.cc)

# Setting the YAML_OUTPUT macro prints out build metadata and core statistics
# in YAML format at the end of the program.
if( YAML_OUTPUT )
    target_compile_definitions(simeng PRIVATE -DYAML_OUTPUT)
endif()

target_include_directories(simeng PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_link_libraries(simeng libsimeng)

install(TARGETS simeng DESTINATION bin)

## Copy default program to install directory. Referenced by main
#install(FILES ${PROJECT_SOURCE_DIR}/SimEngDefaultProgram DESTINATION bin)
#
## Copy default program to binary directory in build folder (Needed when working with some IDEs as it uses the binary which is built here). Referenced by main
#add_custom_command(
#        TARGET simeng POST_BUILD
#        COMMAND ${CMAKE_COMMAND} -E copy
#        ${PROJECT_SOURCE_DIR}/SimEngDefaultProgram
#        ${CMAKE_CURRENT_BINARY_DIR}/SimEngDefaultProgram)
