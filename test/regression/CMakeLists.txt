# Add object library for base regression test fixture class
add_library(regression-test-base OBJECT RegressionTest.cc RegressionTest.hh)

# Include and link to libsimeng
target_include_directories(regression-test-base
                           PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_link_libraries(regression-test-base libsimeng)

# Link to gtest
target_link_libraries(regression-test-base gtest_main)

# Add LLVM includes
target_include_directories(regression-test-base PRIVATE ${LLVM_INCLUDE_DIRS})

# Link to LLVM libraries
#llvm_map_components_to_libnames(LLVM_LIBS aarch64asmparser object)
llvm_map_components_to_libnames(LLVM_LIBS riscvasmparser object)
target_link_libraries(regression-test-base ${LLVM_LIBS})

# Add regression test directories for each architecture
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_subdirectory(aarch64)
add_subdirectory(riscv)

# Link to yaml-cpp libraries
target_link_libraries(regression-test-base yaml-cpp)