add_executable(simeng main.cc)

target_include_directories(simeng PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_include_directories(simeng PRIVATE ${PROJECT_SOURCE_DIR}/external/yaml-cpp)
target_link_libraries(simeng libsimeng yaml-cpp)

install(TARGETS simeng DESTINATION bin)
