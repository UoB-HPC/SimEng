#include "sstsimengtest.hh"

TEST_GROUP(TG1_LLVMAssemble,
           "SSTSimeng_correctly_assembles_instructions_using_LLVM_and_runs_the_"
           "assembled_source_code",
           "fastL1WithParams_config.py", "src",
           R"(
    mov x1, #1
    mov x1, #1
    mov x1, #1
  )")
TEST_CASE(TG1_LLVMAssemble, "Assembly_of_simple_instructions") {
  std::cout << capturedStdout << std::endl;
}
