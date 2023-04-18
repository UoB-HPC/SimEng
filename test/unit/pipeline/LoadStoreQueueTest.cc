#include "../MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/memory/FixedLatencyMemory.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/memory/SimpleMem.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Property;
using ::testing::Return;
using ::testing::ReturnRef;

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
        data({RegisterValue(static_cast<uint8_t>(1))}),
        loadUop(new MockInstruction),
        loadUop2(new MockInstruction),
        storeUop(new MockInstruction),
        storeUop2(new MockInstruction),
        loadUopPtr(loadUop),
        loadUopPtr2(loadUop2),
        storeUopPtr(storeUop),
        storeUopPtr2(storeUop2),
        memory(std::make_shared<memory::FixedLatencyMemory>(1024, latency)),
        connection() {
    // Set up MMU->Memory connection
    mmu = std::make_shared<memory::MMU>(fn);
    port1 = mmu->initPort();
    port2 = memory->initPort();
    connection.connect(port1, port2);
    // Initialise memory to 1s
    memory->sendUntimedData(std::vector<char>(1024, 1), 0, 1024);
    // Set up sensible return values for the load uops
    ON_CALL(*loadUop, isLoad()).WillByDefault(Return(true));
    ON_CALL(*loadUop, getGeneratedAddresses())
        .WillByDefault(ReturnRef(addresses));
    ON_CALL(*loadUop2, isLoad()).WillByDefault(Return(true));
    ON_CALL(*loadUop2, getGeneratedAddresses())
        .WillByDefault(ReturnRef(addresses));

    // Set up sensible return values for the store uop
    ON_CALL(*storeUop, isStoreAddress()).WillByDefault(Return(true));
    ON_CALL(*storeUop, isStoreData()).WillByDefault(Return(true));
    ON_CALL(*storeUop, getGeneratedAddresses())
        .WillByDefault(ReturnRef(addresses));
    ON_CALL(*storeUop, getData()).WillByDefault(ReturnRef(data));
  }

 protected:
  LoadStoreQueue getQueue() {
    if (GetParam()) {
      // Combined queue
      return LoadStoreQueue(
          MAX_COMBINED, mmu, {completionSlots.data(), completionSlots.size()},
          [this](auto registers, auto values) {
            forwardOperandsHandler.forwardOperands(registers, values);
          });
    } else {
      // Split queue
      return LoadStoreQueue(MAX_LOADS, MAX_STORES, mmu,
                            {completionSlots.data(), completionSlots.size()},
                            [this](auto registers, auto values) {
                              forwardOperandsHandler.forwardOperands(registers,
                                                                     values);
                            });
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

    // Add the load operation to the queue in program order
    queue.addLoad(loadUopPtr);

    // Trigger the load first, so it might incorrectly read what was in memory
    // before the store
    queue.startLoad(loadUopPtr);
    loadUop->setExecuted(true);
    loadUop->setCommitReady();

    // Add store operation after load has executed otherwise conflictionMap will
    // prevent the load from executing until after the store
    queue.addStore(storeUopPtr);

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

  std::vector<memory::MemoryAccessTarget> addresses;

  std::vector<RegisterValue> data;

  MockInstruction* loadUop;
  MockInstruction* loadUop2;
  MockInstruction* storeUop;
  MockInstruction* storeUop2;

  std::shared_ptr<Instruction> loadUopPtr;
  std::shared_ptr<Instruction> loadUopPtr2;
  std::shared_ptr<MockInstruction> storeUopPtr;
  std::shared_ptr<MockInstruction> storeUopPtr2;

  MockForwardOperandsHandler forwardOperandsHandler;

  const uint64_t latency = 1;
  VAddrTranslator fn = [](uint64_t vaddr, uint64_t pid) -> uint64_t {
    return vaddr;
  };
  std::shared_ptr<memory::Mem> memory;
  std::shared_ptr<memory::MMU> mmu;

  simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>> connection;
  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      port1;
  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      port2;
};

// Test that a split queue can be constructed correctly
TEST_F(LoadStoreQueueTest, SplitQueue) {
  LoadStoreQueue queue =
      LoadStoreQueue(MAX_LOADS, MAX_STORES, mmu, {nullptr, 0},
                     [](auto registers, auto values) {});

  EXPECT_EQ(queue.isCombined(), false);
  EXPECT_EQ(queue.getLoadQueueSpace(), MAX_LOADS);
  EXPECT_EQ(queue.getStoreQueueSpace(), MAX_STORES);
  EXPECT_EQ(queue.getTotalSpace(), MAX_LOADS + MAX_STORES);
}

// Test that a combined queue can be constructed correctly
TEST_F(LoadStoreQueueTest, CombinedQueue) {
  LoadStoreQueue queue = LoadStoreQueue(MAX_COMBINED, mmu, {nullptr, 0},
                                        [](auto registers, auto values) {});

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

  memory::MemoryReadResult completedRead = {addresses[0], data[0], 1};
  span<memory::MemoryReadResult> completedReads = {&completedRead, 1};

  EXPECT_CALL(*loadUop, getGeneratedAddresses()).Times(AtLeast(1));

  loadUop->delegateExecute();
  loadUop->delegateSupplyData();

  loadUop->setDataPending(addresses.size());

  queue.addLoad(loadUopPtr);

  queue.startLoad(loadUopPtr);

  // Tick the queue to fire off the load request
  queue.tick();

  // Check that a read request is made to the memory interface
  EXPECT_EQ(mmu->hasPendingRequests(), true);
  // Check that the MMU supplies the right data to the instruction
  EXPECT_CALL(*loadUop, supplyData(0, Property(&RegisterValue::get<uint8_t>,
                                               data[0].get<uint8_t>())))
      .Times(1);
  // Tick MMU and Memory to process load request
  mmu->tick();
  memory->tick();
  // Expect a check against finished reads and return the result
  EXPECT_EQ(mmu->hasPendingRequests(), false);

  // Check LSQ detects load has all data and begins execution to assign values
  // to registers
  EXPECT_CALL(*loadUop, execute()).Times(1);

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

  // Check that MMU has no requests
  EXPECT_EQ(mmu->hasPendingRequests(), false);

  queue.startStore(storeUopPtr);
  queue.commitStore(storeUopPtr);
  // Tick the queue to complete the store
  queue.tick();

  // Check that a write request was sent to the mmu
  EXPECT_EQ(mmu->hasPendingRequests(), true);

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
  std::vector<memory::MemoryAccessTarget> storeAddresses = {{0, 2}};
  std::vector<RegisterValue> storeData = {static_cast<uint16_t>(0x0101)};

  // The load will read two bytes, at addresses 1 and 2; this will overlap with
  // the written data at address 1
  std::vector<memory::MemoryAccessTarget> loadAddresses = {{1, 2}};

  EXPECT_CALL(*storeUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(ReturnRef(storeAddresses));
  EXPECT_CALL(*storeUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(ReturnRef(storeData));

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(ReturnRef(loadAddresses));

  // Execute a load-after-store sequence
  bool violation = executeRAWSequence(queue);

  EXPECT_EQ(violation, true);
  EXPECT_EQ(queue.getViolatingLoad(), loadUopPtr);
}

// Tests that the store queue will not claim a violation for an independent load
TEST_P(LoadStoreQueueTest, NoViolation) {
  auto queue = getQueue();

  // A different address to the one being stored to
  std::vector<memory::MemoryAccessTarget> loadAddresses = {{1, 1}};

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(ReturnRef(loadAddresses));

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
  std::vector<memory::MemoryAccessTarget> storeAddresses = {{1, 1}, {2, 1}};
  std::vector<RegisterValue> storeData = {static_cast<uint8_t>(0x01),
                                          static_cast<uint8_t>(0x10)};
  EXPECT_CALL(*storeUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(ReturnRef(storeAddresses));
  EXPECT_CALL(*storeUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(ReturnRef(storeData));

  // Set load address which overlaps on first store address
  std::vector<memory::MemoryAccessTarget> loadAddresses = {{1, 1}};
  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(ReturnRef(loadAddresses));

  // Set load address which overlaps on second store address
  std::vector<memory::MemoryAccessTarget> loadAddresses2 = {{2, 1}};
  EXPECT_CALL(*loadUop2, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(ReturnRef(loadAddresses2));

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

  queue.tick();
}

// Test that when the completion order of loads must be inorder, the completion
// slots are filled in the correct order
TEST_P(LoadStoreQueueTest, inOrderCompletion) {
  std::vector<PipelineBuffer<std::shared_ptr<simeng::Instruction>>>
      completionSlots(2, {1, nullptr});
  LoadStoreQueue queue = LoadStoreQueue(
      MAX_LOADS, MAX_STORES, mmu, {completionSlots.data(), 2},
      [](auto registers, auto values) {}, CompletionOrder::INORDER);

  loadUop->delegateExecute();
  loadUop->delegateSupplyData();
  loadUop2->delegateExecute();
  loadUop2->delegateSupplyData();

  loadUop->setDataPending(1);
  loadUop2->setDataPending(1);
  loadUop->setSequenceId(0);
  loadUop2->setSequenceId(1);
  loadUop->setLSQLatency(3);
  loadUop2->setLSQLatency(1);

  loadUop->setExecuted(true);
  loadUop2->setExecuted(true);

  queue.addLoad(loadUopPtr);
  queue.addLoad(loadUopPtr2);
  queue.startLoad(loadUopPtr);
  queue.startLoad(loadUopPtr2);

  queue.tick();
  queue.tick();
  queue.tick();
  mmu->tick();
  memory->tick();
  queue.tick();
  EXPECT_EQ(completionSlots[0].getTailSlots()[0]->getSequenceId(), 0);
  EXPECT_EQ(completionSlots[1].getTailSlots()[0]->getSequenceId(), 1);
}

// Test that when the completion order of loads must be out-of-order, the
// completion slots are filled in the correct order
TEST_P(LoadStoreQueueTest, OoOCompletion) {
  std::vector<PipelineBuffer<std::shared_ptr<simeng::Instruction>>>
      completionSlots(1, {1, nullptr});
  LoadStoreQueue queue = LoadStoreQueue(
      MAX_LOADS, MAX_STORES, mmu, {completionSlots.data(), 1},
      [](auto registers, auto values) {}, CompletionOrder::OUTOFORDER);

  loadUop->delegateExecute();
  loadUop->delegateSupplyData();
  loadUop2->delegateExecute();
  loadUop2->delegateSupplyData();

  loadUop->setDataPending(1);
  loadUop2->setDataPending(1);

  loadUop->setSequenceId(0);
  loadUop2->setSequenceId(1);
  loadUop->setLSQLatency(3);
  loadUop2->setLSQLatency(1);

  queue.addLoad(loadUopPtr);
  queue.addLoad(loadUopPtr2);
  queue.startLoad(loadUopPtr);
  queue.startLoad(loadUopPtr2);

  queue.tick();
  mmu->tick();
  memory->tick();
  queue.tick();
  EXPECT_EQ(completionSlots[0].getTailSlots()[0]->getSequenceId(), 1);
  queue.tick();
  mmu->tick();
  memory->tick();
  queue.tick();
  EXPECT_EQ(completionSlots[0].getTailSlots()[0]->getSequenceId(), 0);
}

INSTANTIATE_TEST_SUITE_P(LoadStoreQueueTests, LoadStoreQueueTest,
                         ::testing::Values<bool>(false, true));

}  // namespace pipeline
}  // namespace simeng
