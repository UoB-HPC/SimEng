#include "sstsimengtest.hh"

TEST_GROUP(TG0, "SSTSimEng_correctly_assembles_instructions_using_LLVM",
           "fastL1WithParams_config.py", "src",
           R"(
    mov x1, #1
    mov x1, #1
    mov x1, #1
  )")
TEST_CASE(TG0, "Test_asssembly_of_simple_instructions") {
  // If this test doesn't throw an error, means LLVM has succesfully assembled
  // instructions.
}
