#include "../MockInstruction.hh"
#include "../MockMemoryInterface.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Property;
using ::testing::Return;

namespace simeng {
namespace pipeline {

const uint8_t MAX_LOADS = 32;
const uint8_t MAX_STORES = 32;
const uint8_t MAX_COMBINED = 64;

class MockForwardOperandsHandler {
 public:
  MOCK_METHOD2(forwardOperands,
               void(const span<Register>, const span<RegisterValue>));
};

class LoadStoreQueueTest : public ::testing::TestWithParam<bool> {
 public:
  LoadStoreQueueTest()
      : completionSlots({{1, nullptr}}),
        addresses({{0, 1}}),
        addressesSpan({addresses.data(), addresses.size()}),
        data({RegisterValue(static_cast<uint8_t>(1))}),
        dataSpan({data.data(), data.size()}),
        memory{},
        stats("./stats-dump.txt"),
        loadUop(new MockInstruction),
        loadUop2(new MockInstruction),
        storeUop(new MockInstruction),
        storeUop2(new MockInstruction),
        loadUopPtr(loadUop),
        loadUopPtr2(loadUop2),
        storeUopPtr(storeUop),
        storeUopPtr2(storeUop2) {
    // Set up sensible return values for the load uop
    ON_CALL(*loadUop, isLoad()).WillByDefault(Return(true));
    ON_CALL(*loadUop, getGeneratedAddresses())
        .WillByDefault(Return(addressesSpan));

    // Set up sensible return values for the store uop
    ON_CALL(*storeUop, isStoreAddress()).WillByDefault(Return(true));
    ON_CALL(*storeUop, isStoreData()).WillByDefault(Return(true));
    ON_CALL(*storeUop, getGeneratedAddresses())
        .WillByDefault(Return(addressesSpan));
    ON_CALL(*storeUop, getData()).WillByDefault(Return(dataSpan));
  }

 protected:
  LoadStoreQueue getQueue() {
    if (GetParam()) {
      // Combined queue
      return LoadStoreQueue(
          MAX_COMBINED, dataMemory,
          {completionSlots.data(), completionSlots.size()},
          [this](auto registers, auto values) {
            forwardOperandsHandler.forwardOperands(registers, values);
          },
          stats);
    } else {
      // Split queue
      return LoadStoreQueue(
          MAX_LOADS, MAX_STORES, dataMemory,
          {completionSlots.data(), completionSlots.size()},
          [this](auto registers, auto values) {
            forwardOperandsHandler.forwardOperands(registers, values);
          },
          stats);
    }
  }

  /** Constructs and executes a potential read-after-write memory access
   * sequence in the supplied queue, and returns `true` if the queue detected a
   * memory order violation. */
  bool executeRAWSequence(LoadStoreQueue& queue) {
    // Load uop comes sequentially after the store uop, and potentially reads
    // from the same address the store writes to
    storeUop->setSequenceId(0);
    storeUop->setInstructionId(0);
    loadUop->setSequenceId(1);
    loadUop->setInstructionId(1);

    // Add the memory operations to the queue in program order
    queue.addStore(storeUopPtr);
    queue.addLoad(loadUopPtr);

    // Trigger the load first, so it might incorrectly read what was in memory
    // before the store
    queue.startLoad(loadUopPtr);
    loadUop->setExecuted(true);
    loadUop->setCommitReady();

    // Supply data to storeUop
    queue.supplyStoreData(storeUopPtr);

    // Trigger the store, and return any violation
    // TODO: Once a memory interface is in place, ensure the load was
    // resolved before triggering the store
    storeUop->setCommitReady();
    return queue.commitStore(storeUopPtr);
  }

  std::vector<pipeline::PipelineBuffer<std::shared_ptr<Instruction>>>
      completionSlots;

  std::vector<MemoryAccessTarget> addresses;
  span<const MemoryAccessTarget> addressesSpan;

  std::vector<RegisterValue> data;
  span<const RegisterValue> dataSpan;

  char memory[1024];

  MockInstruction* loadUop;
  MockInstruction* loadUop2;
  MockInstruction* storeUop;
  MockInstruction* storeUop2;

  std::shared_ptr<Instruction> loadUopPtr;
  std::shared_ptr<Instruction> loadUopPtr2;
  std::shared_ptr<MockInstruction> storeUopPtr;
  std::shared_ptr<MockInstruction> storeUopPtr2;

  MockForwardOperandsHandler forwardOperandsHandler;

  MockMemoryInterface dataMemory;

  Statistics stats;
};

// Test that a split queue can be constructed correctly
TEST_F(LoadStoreQueueTest, SplitQueue) {
  LoadStoreQueue queue = LoadStoreQueue(
      MAX_LOADS, MAX_STORES, dataMemory, {nullptr, 0},
      [](auto registers, auto values) {}, stats);

  EXPECT_EQ(queue.isCombined(), false);
  EXPECT_EQ(queue.getLoadQueueSpace(), MAX_LOADS);
  EXPECT_EQ(queue.getStoreQueueSpace(), MAX_STORES);
  EXPECT_EQ(queue.getTotalSpace(), MAX_LOADS + MAX_STORES);
}

// Test that a combined queue can be constructed correctly
TEST_F(LoadStoreQueueTest, CombinedQueue) {
  LoadStoreQueue queue = LoadStoreQueue(
      MAX_COMBINED, dataMemory, {nullptr, 0},
      [](auto registers, auto values) {}, stats);

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
  loadUop->setSequenceId(1);
  auto queue = getQueue();

  MemoryReadResult completedRead = {addresses[0], data[0], 1};
  span<MemoryReadResult> completedReads = {&completedRead, 1};

  EXPECT_CALL(*loadUop, getGeneratedAddresses()).Times(AtLeast(1));

  loadUop->setDataPending(addresses.size());

  queue.addLoad(loadUopPtr);

  // Check that a read request is made to the memory interface
  EXPECT_CALL(dataMemory, requestRead(addresses[0], _)).Times(1);

  // Expect a check against finished reads and return the result
  EXPECT_CALL(dataMemory, getCompletedReads())
      .WillRepeatedly(Return(completedReads));

  // Check that the LSQ supplies the right data to the instruction
  // TODO: Replace with check for call over memory interface in future?
  EXPECT_CALL(*loadUop,
              supplyData(0, Property(&RegisterValue::get<uint8_t>, data[0])))
      .Times(1);

  queue.startLoad(loadUopPtr);

  // Tick the queue to complete the load
  queue.tick();
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

  storeUop->setSequenceId(1);
  storeUop->setInstructionId(1);

  queue.addStore(storeUopPtr);
  storeUopPtr->setCommitReady();
  queue.supplyStoreData(storeUopPtr);

  // Check that a write request is sent to the memory interface
  EXPECT_CALL(dataMemory,
              requestWrite(addresses[0],
                           Property(&RegisterValue::get<uint8_t>, data[0])))
      .Times(1);

  queue.commitStore(storeUopPtr);
  // Tick the queue to complete the store
  queue.tick();

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

  // Set the store operation to come before the load in the program order
  storeUop->setSequenceId(0);
  loadUop->setSequenceId(1);

  // First start the load operation before the store to avoid any reordering
  // confliction detection
  queue.addLoad(loadUopPtr);
  queue.startLoad(loadUopPtr);
  loadUop->setExecuted(true);
  loadUop->setCommitReady();

  // Complete a store operation that conflicts with the active load
  queue.addStore(storeUopPtr);
  queue.supplyStoreData(storeUopPtr);
  storeUop->setCommitReady();

  // Expect a violation to be detected
  bool violation = queue.commitStore(storeUopPtr);

  EXPECT_EQ(violation, true);
  EXPECT_EQ(queue.getViolatingLoad(), loadUopPtr);
}

// Tests that committing a store correctly detects a memory order violation
// caused by overlapping (but not matching) memory regions
TEST_P(LoadStoreQueueTest, ViolationOverlap) {
  auto queue = getQueue();

  // The store will write the byte `0x01` at addresses 0 and 1
  std::vector<MemoryAccessTarget> storeAddresses = {{0, 2}};
  std::vector<RegisterValue> storeData = {static_cast<uint16_t>(0x0101)};

  span<const MemoryAccessTarget> storeAddressesSpan = {storeAddresses.data(),
                                                       storeAddresses.size()};
  span<const RegisterValue> storeDataSpan = {storeData.data(),
                                             storeData.size()};

  // The load will read two bytes, at addresses 1 and 2; this will overlap with
  // the written data at address 1
  std::vector<MemoryAccessTarget> loadAddresses = {{1, 2}};
  span<const MemoryAccessTarget> loadAddressesSpan = {loadAddresses.data(),
                                                      loadAddresses.size()};

  EXPECT_CALL(*storeUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(storeAddressesSpan));
  EXPECT_CALL(*storeUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(storeDataSpan));

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(loadAddressesSpan));

  // Execute a load-after-store sequence
  bool violation = executeRAWSequence(queue);

  EXPECT_EQ(violation, true);
  EXPECT_EQ(queue.getViolatingLoad(), loadUopPtr);
}

// Tests that the store queue will not claim a violation for an independent load
TEST_P(LoadStoreQueueTest, NoViolation) {
  auto queue = getQueue();

  // A different address to the one being stored to
  std::vector<MemoryAccessTarget> loadAddresses = {{1, 1}};
  span<const MemoryAccessTarget> loadAddressesSpan = {loadAddresses.data(),
                                                      loadAddresses.size()};

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(loadAddressesSpan));

  // Execute a load-after-store sequence
  bool violation = executeRAWSequence(queue);

  // No violation should have occurred, as the addresses are different
  EXPECT_EQ(violation, false);
}

// Test that a flushed load currently in a state of reordering confliction is
// correctly removed
TEST_P(LoadStoreQueueTest, FlushDuringConfliction) {
  auto queue = getQueue();

  storeUop->setSequenceId(0);
  loadUop->setSequenceId(1);
  loadUop->setFlushed();
  loadUop2->setSequenceId(2);
  loadUop2->setFlushed();

  // Set store addresses and data
  std::vector<MemoryAccessTarget> storeAddresses = {{1, 1}, {2, 1}};
  span<const MemoryAccessTarget> storeAddressesSpan = {storeAddresses.data(),
                                                       storeAddresses.size()};
  std::vector<RegisterValue> storeData = {static_cast<uint8_t>(0x01),
                                          static_cast<uint8_t>(0x10)};
  span<const RegisterValue> storeDataSpan = {storeData.data(),
                                             storeData.size()};
  EXPECT_CALL(*storeUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(storeAddressesSpan));
  EXPECT_CALL(*storeUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(storeDataSpan));

  // Set load address which overlaps on first store address
  std::vector<MemoryAccessTarget> loadAddresses = {{1, 1}};
  span<const MemoryAccessTarget> loadAddressesSpan = {loadAddresses.data(),
                                                      loadAddresses.size()};
  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(loadAddressesSpan));

  // Set load address which overlaps on second store address
  std::vector<MemoryAccessTarget> loadAddresses2 = {{2, 1}};
  span<const MemoryAccessTarget> loadAddressesSpan2 = {loadAddresses2.data(),
                                                       loadAddresses2.size()};
  EXPECT_CALL(*loadUop2, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(loadAddressesSpan2));

  queue.addStore(storeUopPtr);
  queue.addLoad(loadUopPtr);
  queue.addLoad(loadUopPtr2);

  queue.startLoad(loadUopPtr);
  loadUop->setExecuted(true);
  loadUop->setCommitReady();
  queue.startLoad(loadUopPtr2);
  loadUop2->setExecuted(true);
  loadUop2->setCommitReady();
  queue.purgeFlushed();

  queue.supplyStoreData(storeUopPtr);
  bool violation = queue.commitStore(storeUopPtr);

  // No violation should have occurred, as the loads have been flushed
  EXPECT_EQ(violation, false);

  // No read requests as loads have been flushed
  EXPECT_CALL(dataMemory, requestRead(_, _)).Times(0);

  queue.tick();
}

INSTANTIATE_TEST_SUITE_P(LoadStoreQueueTests, LoadStoreQueueTest,
                         ::testing::Values<bool>(false, true));

}  // namespace pipeline
}  // namespace simeng
