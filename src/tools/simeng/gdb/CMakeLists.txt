target_sources(simeng PUBLIC GDBStub.cc)

target_compile_definitions(simeng PUBLIC -DGDB_ENABLED)