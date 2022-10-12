#include "sstsimengtest.hh"

TEST_GROUP(LLVAssembleTG,
           "SSTSimeng correct assembles instructions using LLVM and runs the "
           "assembled source code.",
           "test-llvm-assemble-config.py", "src",
           R"(
    mov w0, wzr
    add w1, w0, #2
    add w2, w0, #7, lsl #12
    add w3, w0, w1, uxtb #1
  )")
TEST_CASE(LLVAssembleTG, "TC1") { std::cout << capturedStdout << std::endl; }