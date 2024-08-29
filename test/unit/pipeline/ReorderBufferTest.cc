#include "../MockBranchPredictor.hh"
#include "../MockInstruction.hh"
#include "../MockMemoryInterface.hh"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"
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
        lsq(
            maxLSQLoads, maxLSQStores, dataMemory, {nullptr, 0},
            [](auto registers, auto values) {}, [](auto uop) {}),
        uop(new MockInstruction),
        uop2(new MockInstruction),
        uop3(new MockInstruction),
        uopPtr(uop),
        uopPtr2(uop2),
        uopPtr3(uop3),
        reorderBuffer(
            maxROBSize, rat, lsq,
            [this](auto insn) { exceptionHandler.raiseException(insn); },
            [this](auto branchAddress) { loopBoundaryAddr = branchAddress; },
            predictor, 4, 2) {}

 protected:
  const uint8_t maxLSQLoads = 32;
  const uint8_t maxLSQStores = 32;
  const uint8_t maxROBSize = 32;

  char memory[1024];
  RegisterAliasTable rat;
  LoadStoreQueue lsq;
  MockBranchPredictor predictor;

  MockExceptionHandler exceptionHandler;

  MockInstruction* uop;
  MockInstruction* uop2;
  MockInstruction* uop3;

  std::shared_ptr<Instruction> uopPtr;
  std::shared_ptr<Instruction> uopPtr2;
  std::shared_ptr<Instruction> uopPtr3;

  MockMemoryInterface dataMemory;

  ReorderBuffer reorderBuffer;

  uint64_t loopBoundaryAddr = 0;
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
  EXPECT_EQ(reorderBuffer.getInstructionsCommittedCount(), 1);
}

// Tests that the reorder buffer won't commit an instruction if it's not ready
TEST_F(ReorderBufferTest, CommitNotReady) {
  reorderBuffer.reserve(uopPtr);

  auto committed = reorderBuffer.commit(1);

  EXPECT_EQ(committed, 0);
  EXPECT_EQ(reorderBuffer.size(), 1);
  EXPECT_EQ(reorderBuffer.getInstructionsCommittedCount(), 0);
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
  EXPECT_EQ(reorderBuffer.getInstructionsCommittedCount(), 0);
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
  EXPECT_EQ(reorderBuffer.getInstructionsCommittedCount(), 2);
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
  EXPECT_EQ(reorderBuffer.getInstructionsCommittedCount(), 1);
}

// Tests that the reorder buffer correctly triggers a store upon commit
TEST_F(ReorderBufferTest, CommitStore) {
  std::vector<memory::MemoryAccessTarget> addresses = {{0, 1}};
  span<const memory::MemoryAccessTarget> addressesSpan = {addresses.data(),
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
  EXPECT_EQ(reorderBuffer.getInstructionsCommittedCount(), 1);

  // Tick lsq to complete store
  lsq.tick();
}

// Tests that the reorder buffer correctly conditionally flushes instructions
// according to their sequence ID
TEST_F(ReorderBufferTest, Flush) {
  reorderBuffer.reserve(uopPtr);
  reorderBuffer.reserve(uopPtr2);

  reorderBuffer.flush(uop->getInstructionId());

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
  EXPECT_EQ(reorderBuffer.getInstructionsCommittedCount(), 1);
}

// Test the reorder buffer correctly sets a macro-op to commitReady when all of
// its associated micro-ops have been
TEST_F(ReorderBufferTest, commitMicroOps) {
  // Reserve all microOps
  uop->setIsMicroOp(true);
  uop->setIsLastMicroOp(false);
  uop2->setIsMicroOp(true);
  uop2->setIsLastMicroOp(false);
  uop3->setIsMicroOp(true);
  uop3->setIsLastMicroOp(true);
  reorderBuffer.reserve(uopPtr);
  reorderBuffer.reserve(uopPtr2);
  reorderBuffer.reserve(uopPtr3);
  EXPECT_EQ(reorderBuffer.size(), 3);

  EXPECT_EQ(uopPtr->getInstructionId(), 0);
  EXPECT_EQ(uopPtr2->getInstructionId(), 0);
  EXPECT_EQ(uopPtr3->getInstructionId(), 0);

  // No micro-ops are waiting commit. Make sure they're not commit ready after
  // call to `commitMicroOps`
  reorderBuffer.commitMicroOps(0);
  EXPECT_FALSE(uopPtr->canCommit());
  EXPECT_FALSE(uopPtr2->canCommit());
  EXPECT_FALSE(uopPtr3->canCommit());

  // Set middle instruction as waitingCommit - ensure still not set commit ready
  uop->setWaitingCommit();
  reorderBuffer.commitMicroOps(0);
  EXPECT_FALSE(uopPtr->canCommit());
  EXPECT_FALSE(uopPtr2->canCommit());
  EXPECT_FALSE(uopPtr3->canCommit());

  // Set last instruction as waitingCommit - ensure still not set commit ready
  uop3->setWaitingCommit();
  reorderBuffer.commitMicroOps(0);
  EXPECT_FALSE(uopPtr->canCommit());
  EXPECT_FALSE(uopPtr2->canCommit());
  EXPECT_FALSE(uopPtr3->canCommit());

  // Set first instruction as waitingCommit - ensure still they are set commit
  // ready now all micro-ops are done
  uop2->setWaitingCommit();
  reorderBuffer.commitMicroOps(0);
  EXPECT_TRUE(uopPtr->canCommit());
  EXPECT_TRUE(uopPtr2->canCommit());
  EXPECT_TRUE(uopPtr3->canCommit());

  // Now call commit in ROB and make sure micro-ops are committed properly
  unsigned int committed = reorderBuffer.commit(3);
  EXPECT_EQ(committed, 3);
  EXPECT_EQ(reorderBuffer.getInstructionsCommittedCount(), 1);
  EXPECT_EQ(reorderBuffer.size(), 0);
}

// Test that a detected violating load in the lsq leads to a flush
TEST_F(ReorderBufferTest, violatingLoad) {
  const uint64_t strAddr = 16;
  const uint64_t strSize = 4;
  const uint64_t ldAddr = 18;
  const uint64_t ldSize = 4;

  // Init Store
  const memory::MemoryAccessTarget strTarget = {strAddr, strSize};
  span<const memory::MemoryAccessTarget> strTargetSpan = {&strTarget, 1};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(Return(strTargetSpan));
  ON_CALL(*uop, isStoreAddress()).WillByDefault(Return(true));
  ON_CALL(*uop, isStoreData()).WillByDefault(Return(true));
  uopPtr->setSequenceId(0);
  uopPtr->setInstructionId(0);
  lsq.addStore(uopPtr);
  reorderBuffer.reserve(uopPtr);
  // Init load
  const memory::MemoryAccessTarget ldTarget = {ldAddr, ldSize};
  span<const memory::MemoryAccessTarget> ldTargetSpan = {&ldTarget, 1};
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(Return(ldTargetSpan));
  ON_CALL(*uop2, isLoad()).WillByDefault(Return(true));
  uopPtr2->setSequenceId(1);
  uopPtr2->setInstructionId(1);
  uopPtr2->setInstructionAddress(4096);
  lsq.addLoad(uopPtr2);
  reorderBuffer.reserve(uopPtr2);

  EXPECT_EQ(reorderBuffer.size(), 2);

  // Start load "Out of order"
  EXPECT_CALL(*uop2, getGeneratedAddresses()).Times(1);
  EXPECT_CALL(*uop, getGeneratedAddresses()).Times(1);
  lsq.startLoad(uopPtr2);

  // Set store "ready to commit" so that violation gets detected
  uopPtr->setCommitReady();
  // Supply Store's data
  RegisterValue strData = RegisterValue(0xABCD, strSize);
  span<const RegisterValue> strDataSpan = {&strData, 1};
  ON_CALL(*uop, getData()).WillByDefault(Return(strDataSpan));
  EXPECT_CALL(*uop, getData()).Times(1);
  lsq.supplyStoreData(uopPtr);

  EXPECT_CALL(*uop, isStoreAddress()).WillOnce(Return(true));
  EXPECT_CALL(*uop, getGeneratedAddresses()).Times(1);        // in LSQ
  EXPECT_CALL(dataMemory, requestWrite(strTarget, strData));  // in LSQ
  EXPECT_CALL(*uop2, getGeneratedAddresses()).Times(1);       // in LSQ
  unsigned int committed = reorderBuffer.commit(4);

  EXPECT_EQ(committed, 1);
  EXPECT_EQ(reorderBuffer.size(), 1);
  EXPECT_TRUE(reorderBuffer.shouldFlush());
  EXPECT_EQ(reorderBuffer.getViolatingLoadsCount(), 1);
  EXPECT_EQ(lsq.getViolatingLoad(), uopPtr2);
  EXPECT_EQ(reorderBuffer.getFlushAddress(), 4096);
  EXPECT_EQ(reorderBuffer.getFlushInsnId(), 0);
}

// Test that a branch is treated as expected, will trigger the loop buffer when
// seen enough times (loop detection threshold set to 2)
TEST_F(ReorderBufferTest, branch) {
  // Set up branch instruction
  const uint64_t insnAddr = 4096;
  const uint64_t branchAddr = 1024;
  BranchPrediction pred = {true, branchAddr};
  ON_CALL(*uop, isBranch()).WillByDefault(Return(true));
  uopPtr->setSequenceId(0);
  uopPtr->setInstructionId(0);
  uopPtr->setInstructionAddress(insnAddr);
  uopPtr->setBranchPrediction(pred);
  uop->setExecuted(true);
  uopPtr->setCommitReady();

  // First pass through ROB -- seen count reset to 0 as new branch
  reorderBuffer.reserve(uopPtr);
  EXPECT_CALL(*uop, isBranch()).Times(2);
  EXPECT_CALL(predictor,
              update(4096, uop->wasBranchTaken(), uop->getBranchAddress(),
                     uop->getBranchType(), uop->getInstructionId()));
  reorderBuffer.commit(1);
  EXPECT_NE(loopBoundaryAddr, insnAddr);

  // Second pass through ROB -- seen count = 1
  reorderBuffer.reserve(uopPtr);
  EXPECT_CALL(*uop, isBranch()).Times(2);
  EXPECT_CALL(predictor,
              update(4096, uop->wasBranchTaken(), uop->getBranchAddress(),
                     uop->getBranchType(), uop->getInstructionId()));
  reorderBuffer.commit(1);
  EXPECT_NE(loopBoundaryAddr, insnAddr);

  // Third pass through ROB -- seen count = 2
  reorderBuffer.reserve(uopPtr);
  EXPECT_CALL(*uop, isBranch()).Times(2);
  EXPECT_CALL(predictor,
              update(4096, uop->wasBranchTaken(), uop->getBranchAddress(),
                     uop->getBranchType(), uop->getInstructionId()));
  reorderBuffer.commit(1);
  EXPECT_NE(loopBoundaryAddr, insnAddr);

  // Fourth pass through ROB -- seen count = 3; exceeds detection theshold,
  // loopBoundaryAddr updated
  reorderBuffer.reserve(uopPtr);
  EXPECT_CALL(*uop, isBranch()).Times(2);
  EXPECT_CALL(predictor,
              update(4096, uop->wasBranchTaken(), uop->getBranchAddress(),
                     uop->getBranchType(), uop->getInstructionId()));
  reorderBuffer.commit(1);
  EXPECT_EQ(loopBoundaryAddr, insnAddr);

  // Update prediction & reset loopBoundaryAddr. Flush ROB to reset loopDetected
  pred = {false, branchAddr + 64};
  uopPtr->setBranchPrediction(pred);
  loopBoundaryAddr = 0;
  reorderBuffer.flush(0);

  // Re-do loop detecition
  // First pass through ROB -- seen count reset to 0 as new branch
  reorderBuffer.reserve(uopPtr);
  EXPECT_CALL(*uop, isBranch()).Times(2);
  EXPECT_CALL(predictor,
              update(4096, uop->wasBranchTaken(), uop->getBranchAddress(),
                     uop->getBranchType(), uop->getInstructionId()));
  reorderBuffer.commit(1);
  EXPECT_NE(loopBoundaryAddr, insnAddr);

  // Second pass through ROB -- seen count = 1
  reorderBuffer.reserve(uopPtr);
  EXPECT_CALL(*uop, isBranch()).Times(2);
  EXPECT_CALL(predictor,
              update(4096, uop->wasBranchTaken(), uop->getBranchAddress(),
                     uop->getBranchType(), uop->getInstructionId()));
  reorderBuffer.commit(1);
  EXPECT_NE(loopBoundaryAddr, insnAddr);

  // Third pass through ROB -- seen count = 2
  reorderBuffer.reserve(uopPtr);
  EXPECT_CALL(*uop, isBranch()).Times(2);
  EXPECT_CALL(predictor,
              update(4096, uop->wasBranchTaken(), uop->getBranchAddress(),
                     uop->getBranchType(), uop->getInstructionId()));
  reorderBuffer.commit(1);
  EXPECT_NE(loopBoundaryAddr, insnAddr);

  // Fourth pass through ROB -- seen count = 3; exceeds detection threshold,
  // loopBoundaryAddr updated
  reorderBuffer.reserve(uopPtr);
  EXPECT_CALL(*uop, isBranch()).Times(2);
  EXPECT_CALL(predictor,
              update(4096, uop->wasBranchTaken(), uop->getBranchAddress(),
                     uop->getBranchType(), uop->getInstructionId()));
  reorderBuffer.commit(1);
  EXPECT_EQ(loopBoundaryAddr, insnAddr);

  // Check that branch misprediction metrics have been correctly collected
  EXPECT_EQ(reorderBuffer.getBranchMispredictedCount(), 8);
}

// Tests that only those destination registers which have been renamed are
// rewound upon a ROB flush
TEST_F(ReorderBufferTest, registerRewind) {
  uop->setInstructionId(0);
  uop->setSequenceId(0);
  uop2->setInstructionId(1);
  uop2->setSequenceId(1);

  // Reserve entries in ROB
  reorderBuffer.reserve(uopPtr);
  reorderBuffer.reserve(uopPtr2);

  // Rename one of the destination registers
  Register archReg = {0, 1, 0};
  Register renamedReg = rat.allocate({0, 1});
  EXPECT_EQ(renamedReg.tag, 32);

  // Set destination registers for to be flushed uop2 with the second register
  // not being renamed
  std::vector<Register> destinations = {renamedReg, {0, 2, 0}};
  const span<Register> destinationSpan = {
      const_cast<Register*>(destinations.data()), 2};
  EXPECT_CALL(*uop2, getDestinationRegisters())
      .Times(1)
      .WillRepeatedly(Return(destinationSpan));

  // Check that mappings in RAT are correct
  EXPECT_EQ(rat.getMapping(archReg).tag, 32);
  EXPECT_EQ(rat.getMapping(destinations[1]).tag, 2);

  // Flush ROB
  reorderBuffer.flush(0);

  // Check rewind occured on only the first destination register
  EXPECT_EQ(rat.getMapping(archReg).tag, 1);
  EXPECT_EQ(rat.getMapping(destinations[1]).tag, 2);
}

}  // namespace pipeline
}  // namespace simeng
