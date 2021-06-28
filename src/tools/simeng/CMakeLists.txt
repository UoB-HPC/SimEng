add_executable(simeng main.cc)

target_include_directories(simeng PUBLIC ${PROJECT_SOURCE_DIR}/src/lib)
target_link_libraries(simeng libsimeng yaml-cpp)

install(TARGETS simeng DESTINATION bin)
