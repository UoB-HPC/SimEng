#include "sstsimengtest.hh"

TEST_GROUP(TG2_LOAD, "Test_Load", "fastL1WithParams_config.py", "src",
           R"( mov x1, #1 )");

TEST_CASE(TG2_LOAD, "Test_single_load_from_memory", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr x1, [x0]
    )",
          "20") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParseMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[1]->data_, 20);
}

TEST_CASE(TG2_LOAD, "Test_multiple_loads_from_memory", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr x1, [x0]
    ldr x1, [x0, #8]
    ldr x1, [x0, #16]
    )",
          "20,40,50") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParseMemReads();
  // skip first two parsed requests as those will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[2]->data_, 20);
  EXPECT_EQ(reads[3]->data_, 40);
  EXPECT_EQ(reads[4]->data_, 50);
}

TEST_CASE(TG2_LOAD, "Test_multiple_loads_from_memory_into_different_registers",
          "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr x1, [x0]
    ldr x2, [x0, #8]
    ldr x3, [x0, #16]
    ldr x4, [x0, #24]
    ldr x5, [x0, #32]
    )",
          "20,40,50,60,70") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParseMemReads();
  // skip first two parsed requests as those will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[2]->data_, 20);
  EXPECT_EQ(reads[3]->data_, 40);
  EXPECT_EQ(reads[4]->data_, 50);
  EXPECT_EQ(reads[5]->data_, 60);
  EXPECT_EQ(reads[6]->data_, 70);
}
