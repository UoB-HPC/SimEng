#include "../MockInstruction.hh"
#include "../MockMemoryInterface.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"
#include "simeng/pipeline/RegisterAliasTable.hh"
#include "simeng/pipeline/ReorderBuffer.hh"

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Property;
using ::testing::Return;

namespace simeng {
namespace pipeline {

class MockExceptionHandler {
 public:
  MOCK_METHOD1(raiseException, void(std::shared_ptr<Instruction> instruction));
};

class ReorderBufferTest : public testing::Test {
 public:
  ReorderBufferTest()
      : memory{},
        rat({{8, 32}}, {64}),
        lsq(maxLSQLoads, maxLSQStores, dataMemory, {nullptr, 0},
            [](auto registers, auto values) {}),
        uop(new MockInstruction),
        uop2(new MockInstruction),
        uopPtr(uop),
        uopPtr2(uop2),
        reorderBuffer(maxROBSize, rat, lsq, [this](auto insn) {
          exceptionHandler.raiseException(insn);
        }) {}

 protected:
  const uint8_t maxLSQLoads = 32;
  const uint8_t maxLSQStores = 32;
  const uint8_t maxROBSize = 32;

  char memory[1024];
  RegisterAliasTable rat;
  LoadStoreQueue lsq;

  MockExceptionHandler exceptionHandler;

  MockInstruction* uop;
  MockInstruction* uop2;

  std::shared_ptr<Instruction> uopPtr;
  std::shared_ptr<MockInstruction> uopPtr2;

  MockMemoryInterface dataMemory;

  ReorderBuffer reorderBuffer;
};

// Tests that an instruction can have a slot reserved in the ROB and be
// allocated a sequence ID
TEST_F(ReorderBufferTest, Reserve) {
  uint64_t oldSeqId = std::numeric_limits<uint64_t>::max();
  uop->setSequenceId(oldSeqId);

  reorderBuffer.reserve(uopPtr);

  // Check that the sequence ID has been changed
  EXPECT_NE(uop->getSequenceId(), oldSeqId);
  EXPECT_EQ(reorderBuffer.size(), 1);
}

// Tests that multiple instruction slots can be reserved, and are allocated
// increasingly larger sequence IDs
TEST_F(ReorderBufferTest, SequenceId) {
  reorderBuffer.reserve(uopPtr);
  reorderBuffer.reserve(uopPtr2);

  EXPECT_LT(uop->getSequenceId(), uop2->getSequenceId());
  EXPECT_EQ(reorderBuffer.size(), 2);
}

// Tests that the amount of free space is correctly reported
TEST_F(ReorderBufferTest, FreeSpace) {
  reorderBuffer.reserve(uopPtr);

  EXPECT_EQ(reorderBuffer.getFreeSpace(), maxROBSize - 1);
}

// Tests that the reorder buffer commits a single ready instruction correctly
TEST_F(ReorderBufferTest, Commit) {
  reorderBuffer.reserve(uopPtr);
  uop->setCommitReady();

  auto committed = reorderBuffer.commit(1);

  EXPECT_EQ(committed, 1);
  EXPECT_EQ(reorderBuffer.size(), 0);
}

// Tests that the reorder buffer won't commit an instruction if it's not ready
TEST_F(ReorderBufferTest, CommitNotReady) {
  reorderBuffer.reserve(uopPtr);

  auto committed = reorderBuffer.commit(1);

  EXPECT_EQ(committed, 0);
  EXPECT_EQ(reorderBuffer.size(), 1);
}

// Tests that the reorder buffer won't commit a ready instruction if it's not at
// the head of the reorder buffer
TEST_F(ReorderBufferTest, CommitHeadNotReady) {
  reorderBuffer.reserve(uopPtr);
  reorderBuffer.reserve(uopPtr2);

  uopPtr2->setCommitReady();

  auto committed = reorderBuffer.commit(1);

  EXPECT_EQ(committed, 0);
  EXPECT_EQ(reorderBuffer.size(), 2);
}

// Tests that the reorder buffer can commit multiple ready instructions
TEST_F(ReorderBufferTest, CommitMultiple) {
  reorderBuffer.reserve(uopPtr);
  reorderBuffer.reserve(uopPtr2);

  uopPtr->setCommitReady();
  uopPtr2->setCommitReady();

  auto committed = reorderBuffer.commit(2);

  EXPECT_EQ(committed, 2);
  EXPECT_EQ(reorderBuffer.size(), 0);
}

// Tests that the reorder buffer correctly informs the LSQ when committing a
// load
TEST_F(ReorderBufferTest, CommitLoad) {
  ON_CALL(*uop, isLoad()).WillByDefault(Return(true));
  lsq.addLoad(uopPtr);

  reorderBuffer.reserve(uopPtr);

  uopPtr->setCommitReady();
  reorderBuffer.commit(1);

  // Check that the load was removed from the LSQ
  EXPECT_EQ(lsq.getLoadQueueSpace(), maxLSQLoads);
}

// Tests that the reorder buffer correctly triggers a store upon commit
TEST_F(ReorderBufferTest, CommitStore) {
  std::vector<MemoryAccessTarget> addresses = {{0, 1}};
  span<const MemoryAccessTarget> addressesSpan = {addresses.data(),
                                                  addresses.size()};

  std::vector<RegisterValue> data = {static_cast<uint8_t>(1)};
  span<const RegisterValue> dataSpan = {data.data(), data.size()};

  ON_CALL(*uop, isStoreAddress()).WillByDefault(Return(true));
  ON_CALL(*uop, isStoreData()).WillByDefault(Return(true));
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(Return(addressesSpan));
  ON_CALL(*uop, getData()).WillByDefault(Return(dataSpan));

  uop->setSequenceId(1);
  uop->setInstructionId(1);

  lsq.addStore(uopPtr);

  reorderBuffer.reserve(uopPtr);

  lsq.supplyStoreData(uopPtr);

  uopPtr->setCommitReady();

  // Check that the correct value will be written to memory
  EXPECT_CALL(
      dataMemory,
      requestWrite(addresses[0], Property(&RegisterValue::get<uint8_t>, 1)))
      .Times(1);

  reorderBuffer.commit(1);

  // Check that the store was committed and removed from the LSQ
  EXPECT_EQ(lsq.getStoreQueueSpace(), maxLSQStores);

  // Tick lsq to complete store
  lsq.tick();
}

// Tests that the reorder buffer correctly conditionally flushes instructions
// according to their sequence ID
TEST_F(ReorderBufferTest, Flush) {
  reorderBuffer.reserve(uopPtr);
  reorderBuffer.reserve(uopPtr2);

  reorderBuffer.flush(uop->getSequenceId());

  EXPECT_EQ(uop->isFlushed(), false);
  EXPECT_EQ(uop2->isFlushed(), true);
  EXPECT_EQ(reorderBuffer.size(), 1);
}

// Tests that an exception-generating instruction raises an exception upon
// commitment
TEST_F(ReorderBufferTest, Exception) {
  reorderBuffer.reserve(uopPtr);

  uop->setCommitReady();
  uop->setExceptionEncountered(true);

  EXPECT_CALL(exceptionHandler, raiseException(uopPtr)).Times(1);

  auto committed = reorderBuffer.commit(1);

  EXPECT_EQ(committed, 1);
}

}  // namespace pipeline
}  // namespace simeng
