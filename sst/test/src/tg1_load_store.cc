#include "sstsimengtest.hh"

TEST_GROUP(TG1, "SSTSimEng_correctly_handles_load_and_store_instructions",
           "fastL1WithParams_config.py", "withSrc=True",
           R"(source= mov x1, #1 )");

TEST_CASE(TG1, "load_of_different_size_from_memory_64bits", "withSrc=True",
          R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr x1, [x0]
    )",
          "heap=348709988") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)348709988);
}

TEST_CASE(TG1, "load_of_different_size_from_memory_32bits", "withSrc=True",
          R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr w1, [x0]
    )",
          "heap=23323") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)23323);
}

TEST_CASE(TG1, "load_of_different_size_from_memory_16bits", "withSrc=True",
          R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrh w1, [x0]
    )",
          "heap=23214") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)23214);
}

TEST_CASE(TG1, "load of_different_size_8bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrb w1, [x0]
    )",
          "heap=120") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)120);
}

TEST_CASE(TG1, "multiple_loads_from_memory_64bit", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr x1, [x0]
    ldr x1, [x0, #8]
    ldr x1, [x0, #16]
    )",
          "heap=20,40,50") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first two parsed requests as those will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 3]->data_, (uint64_t)20);
  EXPECT_EQ(reads[reads.size() - 2]->data_, (uint64_t)40);
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)50);
}

TEST_CASE(TG1, "multiple_loads_from_memory_32bit", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr w1, [x0]
    ldr w1, [x0, #8]
    ldr w1, [x0, #16]
    )",
          "heap=20,40,50") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first two parsed requests as those will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 3]->data_, (uint64_t)20);
  EXPECT_EQ(reads[reads.size() - 2]->data_, (uint64_t)40);
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)50);
}

TEST_CASE(TG1, "multiple_loads_from_memory_16bit", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrh w1, [x0]
    ldrh w1, [x0, #8]
    ldrh w1, [x0, #16]
    )",
          "heap=20,40,50") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first two parsed requests as those will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 3]->data_, (uint64_t)20);
  EXPECT_EQ(reads[reads.size() - 2]->data_, (uint64_t)40);
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)50);
}

TEST_CASE(TG1, "multiple_loads_from_memory_8bit", "withSrc=True",
          R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrb w1, [x0]
    ldrb w1, [x0, #8]
    ldrb w1, [x0, #16]
    )",
          "heap=20,40,50") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first two parsed requests as those will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 3]->data_, (uint64_t)20);
  EXPECT_EQ(reads[reads.size() - 2]->data_, (uint64_t)40);
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)50);
}

TEST_CASE(TG1, "store_then_load_64bit", "withSrc=True", R"(source=
    mov x0, #1
    mov x1, #2048
    str x1, [x0]
    ldr x2, [x0]
    )") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)2048);
}

TEST_CASE(TG1, "store_then_load_32bit", "withSrc=True", R"(source=
    mov x0, #1
    mov w1, #256
    str w1, [x0]
    ldr w2, [x0]
    )") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)256);
}

TEST_CASE(TG1, "store_then_load_16bit", "withSrc=True", R"(source=

    mov x0, #1
    mov w1, #64
    strh w1, [x0]
    ldrh w2, [x0]
    )") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)64);
}

TEST_CASE(TG1, "store_then_load_8bit", "withSrc=True", R"(source=

    mov x0, #1
    mov w1, #8
    strb w1, [x0]
    ldrb w2, [x0]
    )") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)8);
}