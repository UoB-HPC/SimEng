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

// TODO: When the associated requestWrite(...) gets moved into the LSQ's tick()
// functionality, we need to check the state of requestStoreQueue_ and calling
// of requestWrite(...) in a vareity of tests

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
        loadUop(new MockInstruction),
        loadUop2(new MockInstruction),
        storeUop(new MockInstruction),
        storeUop2(new MockInstruction),
        loadStoreUop(new MockInstruction),
        loadUopPtr(loadUop),
        loadUopPtr2(loadUop2),
        storeUopPtr(storeUop),
        storeUopPtr2(storeUop2),
        loadStoreUopPtr(loadStoreUop) {
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
  LoadStoreQueue getQueue(bool exclusive = false,
                          uint16_t loadBandwidth = UINT16_MAX,
                          uint16_t storeBandwidth = UINT16_MAX,
                          uint16_t permittedRequests = UINT16_MAX,
                          uint16_t permittedLoads = UINT16_MAX,
                          uint16_t permittedStores = UINT16_MAX) {
    if (GetParam()) {
      // Combined queue
      return LoadStoreQueue(
          MAX_COMBINED, dataMemory,
          {completionSlots.data(), completionSlots.size()},
          [this](auto registers, auto values) {
            forwardOperandsHandler.forwardOperands(registers, values);
          },
          [](auto uop) {}, exclusive, loadBandwidth, storeBandwidth,
          permittedRequests, permittedLoads, permittedStores);
    } else {
      // Split queue
      return LoadStoreQueue(
          MAX_LOADS, MAX_STORES, dataMemory,
          {completionSlots.data(), completionSlots.size()},
          [this](auto registers, auto values) {
            forwardOperandsHandler.forwardOperands(registers, values);
          },
          [](auto uop) {}, exclusive, loadBandwidth, storeBandwidth,
          permittedRequests, permittedLoads, permittedStores);
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

  std::vector<memory::MemoryAccessTarget> addresses;
  span<const memory::MemoryAccessTarget> addressesSpan;

  std::vector<RegisterValue> data;
  span<const RegisterValue> dataSpan;

  char memory[1024];

  MockInstruction* loadUop;
  MockInstruction* loadUop2;
  MockInstruction* storeUop;
  MockInstruction* storeUop2;
  MockInstruction* loadStoreUop;

  std::shared_ptr<Instruction> loadUopPtr;
  std::shared_ptr<Instruction> loadUopPtr2;
  std::shared_ptr<MockInstruction> storeUopPtr;
  std::shared_ptr<MockInstruction> storeUopPtr2;
  std::shared_ptr<MockInstruction> loadStoreUopPtr;

  MockForwardOperandsHandler forwardOperandsHandler;

  MockMemoryInterface dataMemory;
};

// Test that a split queue can be constructed correctly
TEST_F(LoadStoreQueueTest, SplitQueue) {
  LoadStoreQueue queue = LoadStoreQueue(
      MAX_LOADS, MAX_STORES, dataMemory, {nullptr, 0},
      [](auto registers, auto values) {}, [](auto uop) {});

  EXPECT_EQ(queue.isCombined(), false);
  EXPECT_EQ(queue.getLoadQueueSpace(), MAX_LOADS);
  EXPECT_EQ(queue.getStoreQueueSpace(), MAX_STORES);
  EXPECT_EQ(queue.getTotalSpace(), MAX_LOADS + MAX_STORES);
}

// Test that a combined queue can be constructed correctly
TEST_F(LoadStoreQueueTest, CombinedQueue) {
  LoadStoreQueue queue = LoadStoreQueue(
      MAX_COMBINED, dataMemory, {nullptr, 0},
      [](auto registers, auto values) {}, [](auto uop) {});

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
  memory::MemoryReadResult completedRead = {addresses[0], data[0], 1};
  span<memory::MemoryReadResult> completedReads = {&completedRead, 1};

  // Set load instruction attributes
  loadUop->setSequenceId(0);
  loadUop->setInstructionId(0);
  loadUop2->setSequenceId(1);
  loadUop2->setInstructionId(1);

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(addressesSpan));
  EXPECT_CALL(*loadUop2, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(addressesSpan));

  // Add loads to LSQ
  queue.addLoad(loadUopPtr);
  queue.addLoad(loadUopPtr2);

  // Start the first load so that its accesses can be added to
  // requestLoadQueue_/requestedLoads_ and expect a memory access to be
  // performed
  queue.startLoad(loadUopPtr);
  EXPECT_CALL(dataMemory, requestRead(addresses[0], 0)).Times(1);
  queue.tick();

  // Start the second load so that its accesses can be added to
  // requestLoadQueue_/requestedLoads_ but flush it before it can perform a
  // memory access
  queue.startLoad(loadUopPtr2);
  loadUop->setFlushed();
  loadUop2->setFlushed();
  queue.purgeFlushed();

  // Expect no activity regarding memory accesses or the passing of the load
  // instruction to the output buffer
  EXPECT_CALL(dataMemory, requestRead(_, _)).Times(0);
  EXPECT_CALL(dataMemory, getCompletedReads())
      .WillRepeatedly(Return(completedReads));
  queue.tick();

  EXPECT_EQ(completionSlots[0].getTailSlots()[0], nullptr);
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

  // Set load instruction attributes
  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(addressesSpan));
  loadUop->setLSQLatency(3);

  // Begin load in LSQ
  queue.addLoad(loadUopPtr);
  queue.startLoad(loadUopPtr);

  // Given 3 cycle latency, no requests should occur in the first two ticks of
  // the LSQ
  EXPECT_CALL(dataMemory, requestRead(_, _)).Times(0);
  queue.tick();
  queue.tick();

  // Check that a read request is made to the memory interface
  EXPECT_CALL(dataMemory, requestRead(addresses[0], _)).Times(1);

  // Expect a check against finished reads and return the result
  EXPECT_CALL(dataMemory, getCompletedReads())
      .WillRepeatedly(Return(completedReads));

  // Check that the LSQ supplies the right data to the instruction
  EXPECT_CALL(*loadUop,
              supplyData(addresses[0].address,
                         Property(&RegisterValue::get<uint8_t>, data[0])))
      .Times(1);

  // Tick the queue to complete the load
  queue.tick();

  EXPECT_EQ(completionSlots[0].getTailSlots()[0].get(), loadUop);
}

// Tests that a queue can perform a load with no addresses
TEST_P(LoadStoreQueueTest, LoadWithNoAddresses) {
  loadUop->setSequenceId(1);
  auto queue = getQueue();

  span<const memory::MemoryAccessTarget> emptyAddressesSpan = {};

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(emptyAddressesSpan));

  // Check that a read request isn't made to the memory interface but the load
  // completes in the LSQ
  EXPECT_CALL(dataMemory, requestRead(_, _)).Times(0);
  EXPECT_CALL(*loadUop, execute()).Times(1);

  queue.addLoad(loadUopPtr);
  queue.startLoad(loadUopPtr);

  // Tick the queue to complete the load
  queue.tick();

  EXPECT_EQ(completionSlots[0].getTailSlots()[0].get(), loadUop);
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

  // Set store instruction attributes
  storeUop->setSequenceId(1);
  storeUop->setInstructionId(1);

  EXPECT_CALL(*storeUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(addressesSpan));
  EXPECT_CALL(*storeUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(dataSpan));

  queue.addStore(storeUopPtr);
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

// Tests that a queue can perform a load-store operation
TEST_P(LoadStoreQueueTest, LoadStore) {
  auto queue = getQueue();
  auto initialLoadSpace = queue.getLoadQueueSpace();
  auto initialStoreSpace = queue.getStoreQueueSpace();

  memory::MemoryReadResult completedRead = {addresses[0], data[0], 1};
  span<memory::MemoryReadResult> completedReads = {&completedRead, 1};

  // Set load-store instruction attributes
  loadStoreUop->setSequenceId(1);
  loadStoreUop->setInstructionId(1);

  EXPECT_CALL(*loadStoreUop, isLoad())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*loadStoreUop, isStoreData())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(true));

  EXPECT_CALL(*loadStoreUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(addressesSpan));
  EXPECT_CALL(*loadStoreUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(dataSpan));

  // Register load-store operation and start load portion
  queue.addLoad(loadStoreUopPtr);
  queue.addStore(loadStoreUopPtr);
  queue.startLoad(loadStoreUopPtr);

  // Check that a read request is made to the memory interface
  EXPECT_CALL(dataMemory, requestRead(addresses[0], _)).Times(1);

  // Expect a check against finished reads and return the result
  EXPECT_CALL(dataMemory, getCompletedReads())
      .WillRepeatedly(Return(completedReads));

  // Check that the LSQ supplies the right data to the instruction
  EXPECT_CALL(*loadStoreUop,
              supplyData(addresses[0].address,
                         Property(&RegisterValue::get<uint8_t>, data[0])))
      .Times(1);

  // Tick the queue to complete the load portion of the load-store
  queue.tick();
  EXPECT_EQ(completionSlots[0].getTailSlots()[0].get(), loadStoreUop);

  // Check that a write request is sent to the memory interface
  EXPECT_CALL(dataMemory,
              requestWrite(addresses[0],
                           Property(&RegisterValue::get<uint8_t>, data[0])))
      .Times(1);

  // Commit both potions of the load-store
  queue.commitLoad(loadStoreUopPtr);
  queue.commitStore(loadStoreUopPtr);

  // Check the load-store was removed
  EXPECT_EQ(queue.getLoadQueueSpace(), initialLoadSpace);
  EXPECT_EQ(queue.getStoreQueueSpace(), initialStoreSpace);
}

// Tests that bandwidth restrictions are adhered to in a non-exclusive LSQ
TEST_P(LoadStoreQueueTest, NonExclusiveBandwidthRestriction) {
  auto queue = getQueue(false, 3, 3);

  // Set instruction attributes
  loadUop->setSequenceId(0);
  loadUop->setInstructionId(0);
  storeUop->setSequenceId(1);
  storeUop->setInstructionId(1);
  loadUop2->setSequenceId(2);
  loadUop2->setInstructionId(2);

  std::vector<memory::MemoryAccessTarget> multipleAddresses = {{1, 2}, {2, 2}};
  span<const memory::MemoryAccessTarget> multipleAddressesSpan = {
      multipleAddresses.data(), multipleAddresses.size()};
  std::vector<RegisterValue> storeData = {static_cast<uint8_t>(0x01),
                                          static_cast<uint8_t>(0x10)};
  span<const RegisterValue> storeDataSpan = {storeData.data(),
                                             storeData.size()};

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*storeUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*loadUop2, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*storeUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(storeDataSpan));

  // Add instructions to LSQ and register their accesses to be processed in the
  // tick() function
  queue.addLoad(loadUopPtr);
  queue.addLoad(loadUopPtr2);
  queue.startLoad(loadUopPtr);
  queue.startLoad(loadUopPtr2);
  queue.addStore(storeUopPtr);
  queue.supplyStoreData(storeUopPtr);
  queue.commitStore(storeUopPtr);

  // Set expectations for tick logic based on set restrictions. Only 2 bytes of
  // read and 2 bytes of write accesses should be processed per cycle (in this
  // case that translates to one of the two addresses each uop has to handle).
  EXPECT_CALL(dataMemory, requestRead(_, 0)).Times(1);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 0)).Times(1);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 2)).Times(1);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 2)).Times(1);
  queue.tick();
}

// Tests that bandwidth restrictions are adhered to in an exclusive LSQ
TEST_P(LoadStoreQueueTest, ExclusiveBandwidthRestriction) {
  auto queue = getQueue(true, 3, 3);

  // Set instruction attributes
  loadUop->setSequenceId(0);
  loadUop->setInstructionId(0);
  storeUop->setSequenceId(1);
  storeUop->setInstructionId(1);
  loadUop2->setSequenceId(2);
  loadUop2->setInstructionId(2);

  std::vector<memory::MemoryAccessTarget> multipleAddresses = {{1, 2}, {2, 2}};
  span<const memory::MemoryAccessTarget> multipleAddressesSpan = {
      multipleAddresses.data(), multipleAddresses.size()};
  std::vector<RegisterValue> storeData = {static_cast<uint8_t>(0x01),
                                          static_cast<uint8_t>(0x10)};
  span<const RegisterValue> storeDataSpan = {storeData.data(),
                                             storeData.size()};

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*storeUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*loadUop2, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*storeUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(storeDataSpan));

  // Add instructions to LSQ and register their accesses to be processed in the
  // tick() function
  queue.addLoad(loadUopPtr);
  queue.addLoad(loadUopPtr2);
  queue.startLoad(loadUopPtr);
  queue.startLoad(loadUopPtr2);
  queue.addStore(storeUopPtr);
  queue.supplyStoreData(storeUopPtr);
  queue.commitStore(storeUopPtr);

  // Set expectations for tick logic based on set restrictions. Only 2 bytes of
  // read and 2 bytes of write accesses should be processed per cycle (in this
  // case that translates to one of the two addresses each uop has to handle).
  // However, there cannot be an overlap between load and store bandwidth usage
  // per cycle due to the LSQ being exclusive
  EXPECT_CALL(dataMemory, requestRead(_, _)).Times(0);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, _)).Times(0);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 0)).Times(1);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 0)).Times(1);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 2)).Times(1);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 2)).Times(1);
  queue.tick();
}

// Tests that request restrictions are adhered to in a non-exclusive LSQ
TEST_P(LoadStoreQueueTest, NonExclusiveRequestsRestriction) {
  auto queue = getQueue(false, UINT16_MAX, UINT16_MAX, 2, 2, 1);

  // Set instruction attributes
  loadUop->setSequenceId(0);
  loadUop->setInstructionId(0);
  storeUop->setSequenceId(1);
  storeUop->setInstructionId(1);
  loadUop2->setSequenceId(2);
  loadUop2->setInstructionId(2);

  std::vector<memory::MemoryAccessTarget> multipleAddresses = {{1, 2}, {2, 2}};
  span<const memory::MemoryAccessTarget> multipleAddressesSpan = {
      multipleAddresses.data(), multipleAddresses.size()};
  std::vector<RegisterValue> storeData = {static_cast<uint8_t>(0x01),
                                          static_cast<uint8_t>(0x10)};
  span<const RegisterValue> storeDataSpan = {storeData.data(),
                                             storeData.size()};

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*storeUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*loadUop2, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*storeUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(storeDataSpan));

  // Add instructions to LSQ and register their accesses to be processed in the
  // tick() function
  queue.addLoad(loadUopPtr);
  queue.addLoad(loadUopPtr2);
  queue.startLoad(loadUopPtr);
  queue.startLoad(loadUopPtr2);
  queue.addStore(storeUopPtr);
  queue.supplyStoreData(storeUopPtr);
  queue.commitStore(storeUopPtr);

  // Set expectations for tick logic based on set restrictions. Either 2 reads
  // or 1 read and 1 write should be processed per cycle
  EXPECT_CALL(dataMemory, requestRead(_, 0)).Times(1);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 0)).Times(1);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 2)).Times(2);
  queue.tick();
}

// Tests that request restrictions are adhered to in an exclusive LSQ
TEST_P(LoadStoreQueueTest, ExclusiveRequestsRestriction) {
  auto queue = getQueue(true, UINT16_MAX, UINT16_MAX, 3, 2, 1);

  // Set instruction attributes
  loadUop->setSequenceId(0);
  loadUop->setInstructionId(0);
  storeUop->setSequenceId(1);
  storeUop->setInstructionId(1);
  loadUop2->setSequenceId(2);
  loadUop2->setInstructionId(2);

  std::vector<memory::MemoryAccessTarget> multipleAddresses = {{1, 2}, {2, 2}};
  span<const memory::MemoryAccessTarget> multipleAddressesSpan = {
      multipleAddresses.data(), multipleAddresses.size()};
  std::vector<RegisterValue> storeData = {static_cast<uint8_t>(0x01),
                                          static_cast<uint8_t>(0x10)};
  span<const RegisterValue> storeDataSpan = {storeData.data(),
                                             storeData.size()};

  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*storeUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*loadUop2, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(multipleAddressesSpan));
  EXPECT_CALL(*storeUop, getData())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(storeDataSpan));

  // Add instructions to LSQ and register their accesses to be processed in the
  // tick() function
  queue.addLoad(loadUopPtr);
  queue.addLoad(loadUopPtr2);
  queue.startLoad(loadUopPtr);
  queue.startLoad(loadUopPtr2);
  queue.addStore(storeUopPtr);
  queue.supplyStoreData(storeUopPtr);
  queue.commitStore(storeUopPtr);

  // Set expectations for tick logic based on set restrictions. Only 2 reads and
  // 1 write should be processed per cycle. However, there cannot be an overlap
  // between load and store requests being processed in a single cycle due to
  // the LSQ being exclusive.
  EXPECT_CALL(dataMemory, requestRead(_, _)).Times(0);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, _)).Times(0);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 0)).Times(2);
  queue.tick();
  EXPECT_CALL(dataMemory, requestRead(_, 2)).Times(2);
  queue.tick();
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

  span<const memory::MemoryAccessTarget> storeAddressesSpan = {
      storeAddresses.data(), storeAddresses.size()};
  span<const RegisterValue> storeDataSpan = {storeData.data(),
                                             storeData.size()};

  // The load will read two bytes, at addresses 1 and 2; this will overlap with
  // the written data at address 1
  std::vector<memory::MemoryAccessTarget> loadAddresses = {{1, 2}};
  span<const memory::MemoryAccessTarget> loadAddressesSpan = {
      loadAddresses.data(), loadAddresses.size()};

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
  std::vector<memory::MemoryAccessTarget> loadAddresses = {{1, 1}};
  span<const memory::MemoryAccessTarget> loadAddressesSpan = {
      loadAddresses.data(), loadAddresses.size()};

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
  std::vector<memory::MemoryAccessTarget> storeAddresses = {{1, 1}, {2, 1}};
  span<const memory::MemoryAccessTarget> storeAddressesSpan = {
      storeAddresses.data(), storeAddresses.size()};
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
  std::vector<memory::MemoryAccessTarget> loadAddresses = {{1, 1}};
  span<const memory::MemoryAccessTarget> loadAddressesSpan = {
      loadAddresses.data(), loadAddresses.size()};
  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(loadAddressesSpan));

  // Set load address which overlaps on second store address
  std::vector<memory::MemoryAccessTarget> loadAddresses2 = {{2, 1}};
  span<const memory::MemoryAccessTarget> loadAddressesSpan2 = {
      loadAddresses2.data(), loadAddresses2.size()};
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

// Test that a load access exactly conflicting on a store access (matching
// address and access size no larger) gets its data supplied when the store
// commits
TEST_P(LoadStoreQueueTest, SupplyDataToConfliction) {
  auto queue = getQueue();

  // Set instruction attributes
  storeUop->setSequenceId(0);
  storeUop->setInstructionId(0);
  loadUop->setSequenceId(1);
  loadUop->setInstructionId(1);

  std::vector<memory::MemoryAccessTarget> storeAddresses = {{1, 1}, {2, 1}};
  span<const memory::MemoryAccessTarget> storeAddressesSpan = {
      storeAddresses.data(), storeAddresses.size()};
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

  // Set load addresses which exactly and partially overlaps on first and second
  // store addresses respectively
  std::vector<memory::MemoryAccessTarget> loadAddresses = {
      {1, 1}, {2, 2}, {3, 1}};
  span<const memory::MemoryAccessTarget> loadAddressesSpan = {
      loadAddresses.data(), loadAddresses.size()};
  EXPECT_CALL(*loadUop, getGeneratedAddresses())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(loadAddressesSpan));

  // Add instructions to LSQ
  queue.addStore(storeUopPtr);
  queue.addLoad(loadUopPtr);

  // Supply store data so the store can commit
  queue.supplyStoreData(storeUopPtr);

  // Start the load so the confliction can be registered
  queue.startLoad(loadUopPtr);

  // Two of the accesses don't exactly conflict so they should generate memory
  // accesses
  EXPECT_CALL(dataMemory, requestRead(loadAddresses[1], 1)).Times(1);
  EXPECT_CALL(dataMemory, requestRead(loadAddresses[2], 1)).Times(1);
  queue.tick();

  // The one access which does exactly conflict with a store access should get
  // its data supplied on the store's commitment
  EXPECT_CALL(*loadUop,
              supplyData(loadAddresses[0].address,
                         Property(&RegisterValue::get<uint8_t>, storeData[0])))
      .Times(1);
  queue.commitStore(storeUopPtr);
}

INSTANTIATE_TEST_SUITE_P(LoadStoreQueueTests, LoadStoreQueueTest,
                         ::testing::Values<bool>(false, true));

}  // namespace pipeline
}  // namespace simeng
