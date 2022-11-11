#include "sstsimengtest.hh"

// Only load and store instructions of various types and basic arithmetic
// instructions are checked as LLVM assembly will only be used by the SST
// testing framework, which only tests loads and stores.

TEST_GROUP(TG0, "SSTSimEng_correctly_assembles_instructions_using_LLVM",
           "fastL1WithParams_config.py", "withSrc=True",
           R"(source=
    mov x1, #1
    mov x0, #0
    add x1, x1, x1
    sub x2, x1, x1
    mul x2, x1, x1
    sdiv x2, x1, x1
    cmp x1, x1
    fmov s0, 0.5
    fmov s1, 1.5
    fadd s2, s0, s1
    fsub s2, s1, s0
    fmul s2, s0, s1
    fdiv s2, s1, s0
    str s0, [x1]
    str x0, [x1]
    str w0, [x1]
    strh w0, [x1]
    strb w0, [x1]
    ldr s0, [x1]
    ldr x0, [x1]
    ldr w2, [x1]
    ldrh w2, [x1]
    ldrb w2, [x1]
    ldp s0, s1, [x0]
    ldp x3, x4, [x0]
    ldp w3, w4, [x0]
    st1 {v0.b}[8], [x0], #1
    ptrue p0.d
    st1b {z0.b}, p0, [x0, x1]
    st1d {z2.d}, p0, [z1.d]
    st1w {z2.s}, p0, [x4]
    addvl x1, x1, #1
    str z1, [x1, #4, mul vl]
    ld1r {v0.16b}, [x0]
    ld1r {v1.8b}, [x0], 1
    ld1 {v0.16b}, [x0]
    ld1 {v2.16b, v3.16b}, [x0]
    hlt #0
  )")
TEST_CASE(TG0, "Test_asssembly_of_simple_instructions") {
  size_t pos = capturedStdout.find("[SimEng] retired:");
  std::string retired = "";
  // Extract the retired: <count> string from capturedStdout.
  for (size_t y = pos; y < capturedStdout.length(); y++) {
    if (capturedStdout[y] != '\n') {
      retired += capturedStdout[y];
    } else {
      break;
    }
  }
  // Extract retired instruction count from "retired: <count>" string and cast
  // to uint64_t.
  // Subtract 18 (length of the prefix: "[SimEng] retired:") from retired string
  // to obtain the length of the substring containing the numeric value
  // representing the total number of retired instructions.
  size_t len = retired.length() - 18;
  uint64_t retiredCount = std::stoull(retired.substr(18, len));
  std::cout << "Total instructions retired: " << retiredCount << std::endl;
  // This should be equal to the total number of instructions in the test case.
  EXPECT_EQ(retiredCount, (uint64_t)38);
  std::cout << capturedStdout << std::endl;
}
