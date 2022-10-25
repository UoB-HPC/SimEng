#include "sstsimengtest.hh"

TEST_GROUP(TG2, "SSTSimEng_uses_cache_for_memory_access",
           "fastL1WithParams_config.py", "src", R"( mov x1, #1 )");

TEST_CASE(TG2, "cache_access_of_load_to_same_address", "src",
          R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Setup
    mov x1, #0
    mov x2, #0

    # Execute first load
    ldr x1, [x0]

    # Multiple instructions to wait for load to execute.
    # Can't be replaced by loop to ensure that caching was
    # established by load.
    mov x4, #0
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1

    # Execute last loop
    ldr x1, [x0]
    )",
          "2048") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t firstLoadCycleLatency = reads[1]->endCycle_ - reads[1]->startCycle_;
  uint64_t firstLoadData = reads[1]->data_;
  // check the last entry of the vector to avoid load executed by branch
  // prediction.
  uint64_t lastLoadCycleLatency =
      reads[reads.size() - 1]->endCycle_ - reads[reads.size() - 1]->startCycle_;
  uint64_t lastLoadData = reads[reads.size() - 1]->data_;

  EXPECT_LT(lastLoadCycleLatency, firstLoadCycleLatency);
  EXPECT_EQ(firstLoadData, lastLoadData);
}

TEST_CASE(TG2, "load_after_store_on_same_address_should_be_return_from_cache",
          "src",
          R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Setup
    mov x2, #2048

    # Load from heap - done to determine max clock cycle without any caching.
    ldr x1, [x0]

    # Store value in x3 at address in x2
    str x1, [x2]

    # Multiple instructions to wait for store to execute.
    # Can't be replaced by loop to ensure that caching was
    # established by store.
    mov x4, #0
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1

    # last load
    ldr x4, [x2]

    )",
          "1024") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.
  uint64_t firstLoadCycleLatency = reads[1]->endCycle_ - reads[1]->startCycle_;
  uint64_t firstLoadData = reads[1]->data_;
  uint64_t lastLoadCycleLatency = reads[2]->endCycle_ - reads[2]->startCycle_;
  uint64_t lastLoadData = reads[2]->data_;

  EXPECT_LT(lastLoadCycleLatency, firstLoadCycleLatency);
  EXPECT_EQ((uint64_t)1024, firstLoadData);
  EXPECT_EQ((uint64_t)1024, lastLoadData);
}

TEST_CASE(TG2,
          "multiple_loads_after_stores_on_same_address_should_return_"
          "from_cache",
          "src",
          R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Setup
    mov x2, #2048

    # Load from heap - done to determine max clock cycle without any caching.
    ldr x1, [x0]

    # Store value in x3 at address in x2
    str x1, [x2]
    str x1, [x2, #8]
    str x1, [x2, #16]
    str x1, [x2, #24]
    str x1, [x2, #32]

    # Multiple instructions to wait for all stores to execute.
    # Can't be replaced by loop to ensure that caching was
    # established by store. This sequence is larger to ensure all
    # store instructions have been executed before we execute load
    # instructions.
    mov x4, #0
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1
    add x4, x4, #1

    # last load
    ldr x4, [x2]
    ldr x4, [x2, #8]
    ldr x4, [x2, #16]
    ldr x4, [x2, #24]
    ldr x4, [x2, #32]

    )",
          "1024") {
  Parser p = Parser(capturedStdout);
  std::vector<ParsedMemRead*> reads = p.getParsedMemReads();
  // skip first parsed request as that one will be caused by heap address
  // retrieval into x0.

  // First request to load value from heap, Check if it is equal to initialised
  // data.
  uint64_t firstLoadData = reads[1]->data_;
  EXPECT_EQ((uint64_t)1024, firstLoadData);

  // The access latency specified in fastL1WithParams_config.py is 2 clock
  // cycle. By the time this data is aggregated and delivered to SimEng it
  // incurs an extra clock cycle, as expected this latency is deterministic
  // for all loads from cache. Hence to check if data is returned from cache we
  // can look for clock latencies <= 3.

  // load at addr: [x2]
  uint64_t secondLoadCycleLatency = reads[2]->endCycle_ - reads[2]->startCycle_;
  uint64_t secondLoadData = reads[2]->data_;
  EXPECT_LTE(secondLoadCycleLatency, (uint64_t)3);
  EXPECT_EQ((uint64_t)1024, secondLoadData);
  // load at addr: [x2, #8]
  uint64_t thirdLoadCycleLatency = reads[3]->endCycle_ - reads[3]->startCycle_;
  uint64_t thirdLoadData = reads[3]->data_;
  EXPECT_LTE(thirdLoadCycleLatency, (uint64_t)3);
  EXPECT_EQ((uint64_t)1024, thirdLoadData);
  // load at addr: [x2, #16]
  uint64_t fourthLoadCycleLatency = reads[4]->endCycle_ - reads[4]->startCycle_;
  uint64_t fourthLoadData = reads[4]->data_;
  EXPECT_LTE(fourthLoadCycleLatency, (uint64_t)3);
  EXPECT_EQ((uint64_t)1024, fourthLoadData);
  // load at addr: [x2, #24]
  uint64_t fifthLoadCycleLatency = reads[5]->endCycle_ - reads[5]->startCycle_;
  uint64_t fifthLoadData = reads[5]->data_;
  EXPECT_LTE(fifthLoadCycleLatency, (uint64_t)3);
  EXPECT_EQ((uint64_t)1024, fifthLoadData);
  // load at addr: [x2, #32]
  uint64_t sixthLoadCycleLatency = reads[6]->endCycle_ - reads[6]->startCycle_;
  uint64_t sixthLoadData = reads[6]->data_;
  EXPECT_LTE(sixthLoadCycleLatency, (uint64_t)3);
  EXPECT_EQ((uint64_t)1024, sixthLoadData);
}