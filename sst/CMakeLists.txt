set(SIMENG_SST_SOURCES SimEngCoreWrapper.cc SimEngMemInterface.cc Assemble.cc)

add_library(sstsimeng SHARED ${SIMENG_SST_SOURCES})
# Including SimEng include files and SST include files
target_include_directories(sstsimeng PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(sstsimeng PUBLIC ${SST_INSTALL_DIR}/include)
# Including libsimeng.so
target_include_directories(sstsimeng PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
# Including capstone
target_include_directories(sstsimeng PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(sstsimeng PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# Extra compile flags generate by sst-config --ELEMENT_CXXFLAGS
# The command had to be replaced as some extra flags have already been added using
# target_include_directories and target_compile_definitions.
target_compile_options(sstsimeng PUBLIC -fPIC)

# Bypasses "cannot used typeid with -fno-rtti".This compile flag causes errors in SST source.
target_compile_options(sstsimeng PUBLIC -frtti)
target_compile_options(sstsimeng PUBLIC -g)

# Define statements generated by sst-config --ELEMENT_CXXFLAGS
# SIMENG_ENABLE_SST is used as a preprocessing directive and is defined by us,
# without this definition files in simeng/sst won't compile.
target_compile_definitions(sstsimeng PUBLIC SIMENG_ENABLE_SST __STDC_FORMAT_MACROS HAVE_CONFIG_H)

# Extra link flags generated by sst-config --ELEMENT_LDFLAGS
# The commmand had to be replaced as some extra flags added using target_include_directories
target_link_options(sstsimeng PUBLIC -fno-common LINKER:-undefined,dynamic_lookup)

# Linking libsimeng.so libraries to sstsimeng.so
target_link_libraries(sstsimeng PUBLIC libsimeng)

if (SIMENG_ENABLE_TESTS)
  if(SIMENG_ENABLE_SST_TESTS)
    target_compile_definitions(sstsimeng PUBLIC SIMENG_ENABLE_TESTS SIMENG_ENABLE_SST_TESTS)
    # Add LLVM includes
    target_include_directories(sstsimeng PUBLIC ${LLVM_INCLUDE_DIRS})
    # Link to LLVM libraries
    llvm_map_components_to_libnames(LLVM_LIBS aarch64asmparser object)
    target_link_libraries(sstsimeng PUBLIC ${LLVM_LIBS})
    add_subdirectory(test)
  endif()
endif()

set(SST_SIMENG_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/sst")
set(SST_REGISTER_BASE_COMMAND "sstsimeng sstsimeng_LIBDIR=${SST_SIMENG_INSTALL_DIR}")
set(SST_REGISTER_ELEMENT_COMMAND "SST_ELEMENT_SOURCE sstsimeng=${SST_SIMENG_INSTALL_DIR}")

# Install libsstsimeng.so library into <path_to_simeng_install_dir>/sst
install(TARGETS sstsimeng DESTINATION sst)
# Install SimEngCoreWrapper.hh and SimEngMemInterface.hh into <path_to_simeng_install_dir>/include
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include
        DESTINATION ${SST_SIMENG_INSTALL_DIR})
# Install SST config into <path_to_simeng_install_dir>/config
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/config
        DESTINATION ${SST_SIMENG_INSTALL_DIR})

# Execute the sst-register command from the command-line to register the sstsimeng
# library with SST.
install(CODE "execute_process(COMMAND sst-register ${SST_REGISTER_BASE_COMMAND} COMMAND_ECHO STDOUT)")
install(CODE "execute_process(COMMAND sst-register ${SST_REGISTER_ELEMENT_COMMAND} COMMAND_ECHO STDOUT)")
