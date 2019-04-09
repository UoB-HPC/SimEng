#include "../MockInstruction.hh"
#include "Instruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pipeline/LoadStoreQueue.hh"

using ::testing::AtLeast;
using ::testing::Property;
using ::testing::Return;

namespace simeng {
namespace pipeline {

const uint8_t MAX_LOADS = 32;
const uint8_t MAX_STORES = 32;
const uint8_t MAX_COMBINED = 64;

class LoadStoreQueueTest : public ::testing::TestWithParam<bool> {
 public:
  LoadStoreQueueTest()
      : addresses({{0, 1}}),
        data({RegisterValue(static_cast<uint8_t>(1))}),
        memory{},
        loadUop(new MockInstruction),
        storeUop(new MockInstruction),
        loadUopPtr(loadUop),
        storeUopPtr(storeUop) {
    // Set up sensible return values for the load uop
    ON_CALL(*loadUop, isLoad()).WillByDefault(Return(true));
    ON_CALL(*loadUop, getGeneratedAddresses()).WillByDefault(Return(addresses));

    // Set up sensible return values for the store uop
    ON_CALL(*storeUop, isStore()).WillByDefault(Return(true));
    ON_CALL(*storeUop, getGeneratedAddresses())
        .WillByDefault(Return(addresses));
    ON_CALL(*storeUop, getData()).WillByDefault(Return(data));
  }

 protected:
  LoadStoreQueue getQueue() {
    if (GetParam()) {
      // Combined queue
      return LoadStoreQueue(MAX_COMBINED, memory);
    } else {
      // Split queue
      return LoadStoreQueue(MAX_LOADS, MAX_STORES, memory);
    }
  }

  /** Constructs and executes a potential read-after-write memory access
   * sequence in the supplied queue, and returns `true` if the queue detected a
   * memory order violation. */
  bool executeRAWSequence(LoadStoreQueue& queue) {
    // Load uop comes sequentially after the store uop, and potentially reads
    // from the same address the store writes to
    storeUop->setSequenceId(0);
    loadUop->setSequenceId(1);

    // Add the memory operations to the queue in program order
    queue.addStore(storeUopPtr);
    queue.addLoad(loadUopPtr);

    // Trigger the load first, so it might incorrectly read what was in memory
    // before the store
    queue.startLoad(loadUopPtr);
    loadUop->setExecuted(true);
    loadUop->setCommitReady();

    // Trigger the store, and return any violation
    // TODO: Once a memory interface is in place, ensure the load was resolved
    // before triggering the store
    storeUop->setCommitReady();
    return queue.commitStore(storeUopPtr);
  }

  std::vector<std::pair<uint64_t, uint8_t>> addresses;
  std::vector<RegisterValue> data;

  char memory[1024];

  MockInstruction* loadUop;
  MockInstruction* storeUop;

  std::shared_ptr<Instruction> loadUopPtr;
  std::shared_ptr<MockInstruction> storeUopPtr;
};

// Test that a split queue can be constructed correctly
TEST_F(LoadStoreQueueTest, SplitQueue) {
  LoadStoreQueue queue = LoadStoreQueue(MAX_LOADS, MAX_STORES, nullptr);

  EXPECT_EQ(queue.isCombined(), false);
  EXPECT_EQ(queue.getLoadQueueSpace(), MAX_LOADS);
  EXPECT_EQ(queue.getStoreQueueSpace(), MAX_STORES);
  EXPECT_EQ(queue.getTotalSpace(), MAX_LOADS + MAX_STORES);
}

// Test that a combined queue can be constructed correctly
TEST_F(LoadStoreQueueTest, CombinedQueue) {
  LoadStoreQueue queue = LoadStoreQueue(MAX_COMBINED, nullptr);

  EXPECT_EQ(queue.isCombined(), true);
  EXPECT_EQ(queue.getLoadQueueSpace(), MAX_COMBINED);
  EXPECT_EQ(queue.getStoreQueueSpace(), MAX_COMBINED);
  EXPECT_EQ(queue.getTotalSpace(), MAX_COMBINED);
}

// Tests that a load can be added to the queue
TEST_P(LoadStoreQueueTest, AddLoad) {
  auto queue = getQueue();
  auto initialLoadSpace = queue.getLoadQueueSpace();
  auto initialStoreSpace = queue.getStoreQueueSpace();
  auto initialTotalSpace = queue.getTotalSpace();

  queue.addLoad(loadUopPtr);

  EXPECT_EQ(queue.getLoadQueueSpace(), initialLoadSpace - 1);
  EXPECT_EQ(queue.getTotalSpace(), initialTotalSpace - 1);

  if (queue.isCombined()) {
    // Combined queue: adding a load should reduce space for stores
    EXPECT_EQ(queue.getStoreQueueSpace(), initialStoreSpace - 1);
  } else {
    // Split queue: adding a load shouldn't affect space for stores
    EXPECT_EQ(queue.getStoreQueueSpace(), initialStoreSpace);
  }
}

// Tests that a store can be added to the queue
TEST_P(LoadStoreQueueTest, AddStore) {
  auto queue = getQueue();
  auto initialLoadSpace = queue.getLoadQueueSpace();
  auto initialStoreSpace = queue.getStoreQueueSpace();
  auto initialTotalSpace = queue.getTotalSpace();

  queue.addStore(storeUopPtr);

  EXPECT_EQ(queue.getStoreQueueSpace(), initialStoreSpace - 1);
  EXPECT_EQ(queue.getTotalSpace(), initialTotalSpace - 1);

  if (queue.isCombined()) {
    // Combined queue: adding a store should reduce space for loads
    EXPECT_EQ(queue.getLoadQueueSpace(), initialLoadSpace - 1);
  } else {
    // Split queue: adding a store shouldn't affect space for loads
    EXPECT_EQ(queue.getLoadQueueSpace(), initialLoadSpace);
  }
}

// Tests that a queue can purge flushed load instructions
TEST_P(LoadStoreQueueTest, PurgeFlushedLoad) {
  auto queue = getQueue();
  auto initialLoadSpace = queue.getLoadQueueSpace();
  queue.addLoad(loadUopPtr);

  loadUop->setFlushed();
  queue.purgeFlushed();

  EXPECT_EQ(queue.getLoadQueueSpace(), initialLoadSpace);
}

// Tests that a queue can purge flushed store instructions
TEST_P(LoadStoreQueueTest, PurgeFlushedStore) {
  auto queue = getQueue();
  auto initialStoreSpace = queue.getStoreQueueSpace();
  queue.addStore(storeUopPtr);

  storeUop->setFlushed();
  queue.purgeFlushed();

  EXPECT_EQ(queue.getStoreQueueSpace(), initialStoreSpace);
}

// Tests that a queue can perform a load
TEST_P(LoadStoreQueueTest, Load) {
  auto queue = getQueue();
  memory[0] = 1;

  EXPECT_CALL(*loadUop, getGeneratedAddresses()).Times(AtLeast(1));

  queue.addLoad(loadUopPtr);

  // Check that the request reads the correct value from memory (a single byte
  // of value `memory[0]`)
  // TODO: Replace with check for call over memory interface in future?
  EXPECT_CALL(*loadUop,
              supplyData(0, Property(&RegisterValue::get<uint8_t>, memory[0])))
      .Times(1);

  queue.startLoad(loadUopPtr);
}

// Tests that a queue can commit a load
TEST_P(LoadStoreQueueTest, CommitLoad) {
  auto queue = getQueue();
  auto initialLoadSpace = queue.getLoadQueueSpace();

  queue.addLoad(loadUopPtr);
  queue.startLoad(loadUopPtr);

  queue.commitLoad(loadUopPtr);

  // Check that the load has left the queue
  EXPECT_EQ(queue.getLoadQueueSpace(), initialLoadSpace);
}

// Tests that a queue can perform a store
TEST_P(LoadStoreQueueTest, Store) {
  auto queue = getQueue();
  auto initialStoreSpace = queue.getStoreQueueSpace();

  EXPECT_CALL(*storeUop, getGeneratedAddresses()).Times(AtLeast(1));
  EXPECT_CALL(*storeUop, getData()).Times(AtLeast(1));

  queue.addStore(storeUopPtr);
  storeUopPtr->setCommitReady();
  queue.commitStore(storeUopPtr);

  // TODO: Replace with check for call over memory interface in future?
  EXPECT_EQ(memory[0], 1);
  // Check the store was removed
  EXPECT_EQ(queue.getStoreQueueSpace(), initialStoreSpace);
}

// Tests that committing a store will correctly detect a direct memory order
// violation
TEST_P(LoadStoreQueueTest, Violation) {
  auto queue = getQueue();

  EXPECT_CALL(*storeUop, getGeneratedAddresses()).Times(AtLeast(1));
  EXPECT_CALL(*storeUop, getData()).Times(AtLeast(1));

  EXPECT_CALL(*loadUop, getGeneratedAddresses()).Times(AtLeast(1));

  // Execute a load-after-store sequence
  bool violation = executeRAWSequence(queue);

  EXPECT_EQ(violation, true);
  EXPECT_EQ(queue.getViolatingLoad(), loadUopPtr);
}

// Tests that committing a store correctly detects a memory order violation
// caused by overlapping (but not matching) memory regions
TEST_P(LoadStoreQueueTest, ViolationOverlap) {
  auto queue = getQueue();

  // The store will write the byte `0x01` at addresses 0 and 1
  std::vector<std::pair<uint64_t, uint8_t>> storeAddresses = {{0, 2}};
  std::vector<RegisterValue> storeData = {static_cast<uint16_t>(0x0101)};

  // The load will read two bytes, at addresses 1 and 2; this will overlap with
  // the written data at address 1
  std::vector<std::pair<uint64_t, uint8_t>> loadAddresses = {{1, 2}};

  EXPECT_CALL(*storeUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(storeAddresses));
  EXPECT_CALL(*storeUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(storeData));

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(loadAddresses));

  // Execute a load-after-store sequence
  bool violation = executeRAWSequence(queue);

  EXPECT_EQ(violation, true);
  EXPECT_EQ(queue.getViolatingLoad(), loadUopPtr);
}

// Tests that the store queue will not claim a violation for an independent load
TEST_P(LoadStoreQueueTest, NoViolation) {
  auto queue = getQueue();

  // A different address to the one being stored to
  std::vector<std::pair<uint64_t, uint8_t>> loadAddresses = {{1, 1}};

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(loadAddresses));

  // Execute a load-after-store sequence
  bool violation = executeRAWSequence(queue);

  // No violation should have occurred, as the addresses are different
  EXPECT_EQ(violation, false);
}

INSTANTIATE_TEST_SUITE_P(LoadStoreQueueTests, LoadStoreQueueTest,
                         ::testing::Values<bool>(false, true));

}  // namespace pipeline
}  // namespace simeng
