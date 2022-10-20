#include "sstsimengtest.hh"

TEST_GROUP(TG1, "SSTSimEng_correctly_handles_load_and_store_instructions",
           "fastL1WithParams_config.py", "src", R"( mov x1, #1 )");

TEST_CASE(TG1, "load_of_different_size_from_memory_64bits", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr x1, [x0]
    )",
          "348709988") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[1]->data_, 348709988);
}

TEST_CASE(TG1, "load_of_different_size_from_memory_32bits", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr w1, [x0]
    )",
          "23323") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[1]->data_, 23323);
}

TEST_CASE(TG1, "load_of_different_size_from_memory_16bits", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrh w1, [x0]
    )",
          "23214") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[1]->data_, 23214);
}

TEST_CASE(TG1, "load of_different_size_8bits", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrb w1, [x0]
    )",
          "120") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[1]->data_, 120);
}

TEST_CASE(TG1, "multiple_loads_from_memory_64bit", "src", R"(
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
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first two parsed requests as those will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[2]->data_, 20);
  EXPECT_EQ(reads[3]->data_, 40);
  EXPECT_EQ(reads[4]->data_, 50);
}

TEST_CASE(TG1, "multiple_loads_from_memory_32bit", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr w1, [x0]
    ldr w1, [x0, #8]
    ldr w1, [x0, #16]
    )",
          "20,40,50") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first two parsed requests as those will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[2]->data_, 20);
  EXPECT_EQ(reads[3]->data_, 40);
  EXPECT_EQ(reads[4]->data_, 50);
}

TEST_CASE(TG1, "multiple_loads_from_memory_16bit", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrh w1, [x0]
    ldrh w1, [x0, #8]
    ldrh w1, [x0, #16]
    )",
          "20,40,50") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first two parsed requests as those will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[2]->data_, 20);
  EXPECT_EQ(reads[3]->data_, 40);
  EXPECT_EQ(reads[4]->data_, 50);
}

TEST_CASE(TG1, "multiple_loads_from_memory_8bit", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrb w1, [x0]
    ldrb w1, [x0, #8]
    ldrb w1, [x0, #16]
    )",
          "20,40,50") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first two parsed requests as those will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[2]->data_, 20);
  EXPECT_EQ(reads[3]->data_, 40);
  EXPECT_EQ(reads[4]->data_, 50);
}

TEST_CASE(TG1, "store_than_load_64bit", "src", R"(

    mov x0, #1
    mov x1, #2048
    str x1, [x0]
    ldr x2, [x0]
    )",
          "") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  EXPECT_EQ(reads[0]->data_, 2048);
}

TEST_CASE(TG1, "store_than_load_32bit", "src", R"(

    mov x0, #1
    mov w1, #256
    str w1, [x0]
    ldr w2, [x0]
    )",
          "") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  EXPECT_EQ(reads[0]->data_, 256);
}

TEST_CASE(TG1, "store_than_load_16bit", "src", R"(

    mov x0, #1
    mov w1, #64
    strh w1, [x0]
    ldrh w2, [x0]
    )",
          "") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  EXPECT_EQ(reads[0]->data_, 64);
}

TEST_CASE(TG1, "store_than_load_8bit", "src", R"(

    mov x0, #1
    mov w1, #8
    strb w1, [x0]
    ldrb w2, [x0]
    )",
          "") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  EXPECT_EQ(reads[0]->data_, 8);
}