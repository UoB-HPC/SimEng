#include "sstsimengtest.hh"

TEST_GROUP(TG3, "SSTSimEng_splits_requests_larger_than_cache_line_width",
           "fastL1WithParams_config.py", "withSrc=True",
           R"(source= mov x1, #1 )");

TEST_CASE(TG3, "Clw_8_bits_req_size_64bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr x1, [x0]
    )",
          "heap=10", "clw=1") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)8);
}

TEST_CASE(TG3, "Clw_8_bits_req_size_32bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr w1, [x0]
    )",
          "heap=10", "clw=1") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)4);
}

TEST_CASE(TG3, "Clw_8_bits_req_size_16bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrh w1, [x0]
    )",
          "heap=10", "clw=1") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)2);
}

TEST_CASE(TG3, "Clw_8_bits_req_size_8bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrb w1, [x0]
    )",
          "heap=10", "clw=1") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)1);
}

TEST_CASE(TG3, "Clw_16_bits_req_size_64bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr x1, [x0]
    )",
          "heap=10", "clw=2") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)4);
}

TEST_CASE(TG3, "Clw_16_bits_req_size_32bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr w1, [x0]
    )",
          "heap=10", "clw=2") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)2);
}

TEST_CASE(TG3, "Clw_16_bits_req_size_16bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrh w1, [x0]
    )",
          "heap=10", "clw=2") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)1);
}

TEST_CASE(TG3, "Clw_16_bits_req_size_8bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrb w1, [x0]
    )",
          "heap=10", "clw=2") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)1);
}

TEST_CASE(TG3, "Clw_32_bits_req_size_64bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr x1, [x0]
    )",
          "heap=10", "clw=4") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)2);
}

TEST_CASE(TG3, "Clw_32_bits_req_size_32bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr w1, [x0]
    )",
          "heap=10", "clw=4") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)1);
}

TEST_CASE(TG3, "Clw_32_bits_req_size_16bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrh w1, [x0]
    )",
          "heap=10", "clw=4") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)1);
}

TEST_CASE(TG3, "Clw_32_bits_req_size_8bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrb w1, [x0]
    )",
          "heap=10", "clw=4") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)1);
}

TEST_CASE(TG3, "Clw_64_bits_req_size_64bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr x1, [x0]
    )",
          "heap=10", "clw=8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)1);
}

TEST_CASE(TG3, "Clw_64_bits_req_size_32bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr w1, [x0]
    )",
          "heap=10", "clw=8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.214
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)1);
}

TEST_CASE(TG3, "Clw_64_bits_req_size_16bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrh w1, [x0]
    )",
          "heap=10", "clw=8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)1);
}

TEST_CASE(TG3, "Clw_64_bits_req_size_8bits", "withSrc=True", R"(source=
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldrb w1, [x0]
    )",
          "heap=10", "clw=8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  EXPECT_EQ(reads[reads.size() - 1]->data_, (uint64_t)10);
  EXPECT_EQ(reads[reads.size() - 1]->numReqs_, (uint64_t)1);
}
