#include "sstsimengtest.hh"

TEST_GROUP(TG4, "SSTSimEng_handles_misaligned_memory_requests",
           "fastL1WithParams_config.py", "src", R"( mov x1, #1 )");

TEST_CASE(TG4, "16_bit_cache_line_to_retrieve_16_bit_data", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #127
    ldrh w1, [x0]
    strh w1, [x4]
    ldrh w1, [x4]
    )",
          "128", "2") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)128);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "16_bit_cache_line_to_retrieve_32_bit_data", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #127
    ldr w1, [x0]
    str w1, [x4]
    ldr w1, [x4]
    )",
          "128", "2") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)128);
  EXPECT_EQ(numReqs, (uint64_t)3);
}

TEST_CASE(TG4, "16_bit_cache_line_to_retrieve_64_bit_data", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #127
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "12", "2") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)12);
  EXPECT_EQ(numReqs, (uint64_t)5);
}

TEST_CASE(TG4, "32_bit_cache_line_to_retrieve_16_bit_data", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #127
    ldrh w1, [x0]
    strh w1, [x4]
    ldrh w1, [x4]
    )",
          "128", "4") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)128);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "32_bit_cache_line_to_retrieve_32_bit_data_#1", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #126
    ldr w1, [x0]
    str w1, [x4]
    ldr w1, [x4]
    )",
          "256", "4") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "32_bit_cache_line_to_retrieve_32_bit_data_#2", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #125
    ldr w1, [x0]
    str w1, [x4]
    ldr w1, [x4]
    )",
          "256", "4") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "32_bit_cache_line_to_retrieve_64_bit_data_#1", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #127
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "4") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)3);
}

TEST_CASE(TG4, "32_bit_cache_line_to_retrieve_64_bit_data_#2", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #126
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "4") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)3);
}

TEST_CASE(TG4, "32_bit_cache_line_to_retrieve_64_bit_data_#3", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #125
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "4") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)3);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_16_bit_data", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #127
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_32_bit_data_#1", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #127
    ldr w1, [x0]
    str w1, [x4]
    ldr w1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_32_bit_data_#2", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #126
    ldr w1, [x0]
    str w1, [x4]
    ldr w1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_32_bit_data_#3", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #125
    ldr w1, [x0]
    str w1, [x4]
    ldr w1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_64_bit_data_#1", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #127
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_64_bit_data_#2", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #126
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_64_bit_data_#3", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #125
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_64_bit_data_#4", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #124
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_64_bit_data_#5", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #123
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_64_bit_data_#6", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #122
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}

TEST_CASE(TG4, "64_bit_cache_line_to_retrieve_64_bit_data_#7", "src", R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x4, #121
    ldr x1, [x0]
    str x1, [x4]
    ldr x1, [x4]
    )",
          "256", "8") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t data = reads[reads.size() - 1]->data_;
  uint64_t numReqs = reads[reads.size() - 1]->numReqs_;
  EXPECT_EQ(data, (uint64_t)256);
  EXPECT_EQ(numReqs, (uint64_t)2);
}