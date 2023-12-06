#include "../MockArchitecture.hh"
#include "../MockBranchPredictor.hh"
#include "../MockInstruction.hh"
#include "../MockMemoryInterface.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/pipeline/FetchUnit.hh"
#include "simeng/pipeline/PipelineBuffer.hh"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Field;
using ::testing::Return;
using ::testing::SetArgReferee;

namespace simeng {
namespace pipeline {

class PipelineFetchUnitTest : public testing::Test {
 public:
  PipelineFetchUnitTest()
      : output(1, {}),
        fetchBuffer({{0, 16}, 0, 0}),
        completedReads(&fetchBuffer, 1),
        fetchUnit(output, memory, 1024, 0, blockSize, isa, predictor),
        uop(new MockInstruction),
        uopPtr(uop) {
    uopPtr->setInstructionAddress(0);
  }

 protected:
  const uint8_t insnMaxSizeBytes = 4;
  const uint8_t blockSize = 16;

  PipelineBuffer<MacroOp> output;
  MockMemoryInterface memory;
  MockArchitecture isa;
  MockBranchPredictor predictor;

  MemoryReadResult fetchBuffer;
  span<MemoryReadResult> completedReads;

  FetchUnit fetchUnit;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
};

// Tests that ticking a fetch unit attempts to predecode from the correct
// program counter and generates output correctly.
TEST_F(PipelineFetchUnitTest, Tick) {
  MacroOp macroOp = {uopPtr};

  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));

  // Set the output parameter to a 1-wide macro-op
  EXPECT_CALL(isa, predecode(_, _, 0, _))
      .WillOnce(DoAll(SetArgReferee<3>(macroOp), Return(4)));

  fetchUnit.tick();

  // Verify that the macro-op was pushed to the output
  EXPECT_EQ(output.getTailSlots()[0].size(), 1);
}

// Tests that ticking a fetch unit does nothing if the output has stalled
TEST_F(PipelineFetchUnitTest, TickStalled) {
  output.stall(true);

  // Anticipate testing instruction type; return true for branch
  ON_CALL(*uop, isBranch()).WillByDefault(Return(true));

  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);

  EXPECT_CALL(predictor, predict(_, _, _)).Times(0);

  fetchUnit.tick();

  // Verify that nothing was pushed to the output
  EXPECT_EQ(output.getTailSlots()[0].size(), 0);
}

// Tests that the fetch unit will handle instructions that straddle fetch block
// boundaries by automatically requesting the next block of data.
TEST_F(PipelineFetchUnitTest, FetchUnaligned) {
  MacroOp mOp = {uopPtr};
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  // Set PC to 14, so there will not be enough data to start decoding
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);
  fetchUnit.updatePC(14);
  fetchUnit.tick();

  // Expect a block starting at address 16 to be requested when we fetch again
  EXPECT_CALL(memory, requestRead(Field(&MemoryAccessTarget::address, 16), _))
      .Times(1);
  fetchUnit.requestFromPC();

  // Tick again, expecting that decoding will now resume
  MemoryReadResult nextBlockValue = {{16, blockSize}, 0, 1};
  span<MemoryReadResult> nextBlock = {&nextBlockValue, 1};
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(nextBlock));
  ON_CALL(isa, predecode(_, _, _, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(4)));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(memory, clearCompletedReads()).Times(4);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(8);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(4);

  // Tick 4 times to process all 16 bytes of fetched data
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }
  // Tick a 5th time to ensure all buffered bytes have been used
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);
  fetchUnit.tick();
}

// Tests that a properly aligned PC (to the fetch block boundary) is correctly
// fetched
TEST_F(PipelineFetchUnitTest, fetchAligned) {
  const uint8_t pc = 16;

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));

  MemoryAccessTarget target = {pc, blockSize};
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, requestRead(target, _)).Times(1);

  // Request block from Memory
  fetchUnit.updatePC(pc);
  fetchUnit.requestFromPC();

  MacroOp mOp = {uopPtr};
  MemoryReadResult memReadResult = {target, RegisterValue(0xFFFF, blockSize),
                                    1};
  span<MemoryReadResult> nextBlock = {&memReadResult, 1};
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(nextBlock));
  ON_CALL(isa, predecode(_, _, _, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(4)));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(memory, clearCompletedReads()).Times(4);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(8);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(4);

  // Tick 4 times to process all 16 bytes of fetched data
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }
  // Tick a 5th time to ensure all buffered bytes have been used
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(memory, clearCompletedReads()).Times(0);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);
  fetchUnit.tick();
}

// Tests that halting functionality triggers correctly
TEST_F(PipelineFetchUnitTest, halted) {
  EXPECT_FALSE(fetchUnit.hasHalted());
  fetchUnit.tick();
  EXPECT_FALSE(fetchUnit.hasHalted());

  // Test PC >= programByteLength triggers halting
  fetchUnit.updatePC(1024);
  EXPECT_TRUE(fetchUnit.hasHalted());

  // Test PC being incremented to >= programByteLength triggers halting
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  fetchUnit.updatePC(1008);
  EXPECT_FALSE(fetchUnit.hasHalted());

  MemoryAccessTarget target = {1008, blockSize};
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, requestRead(target, _)).Times(1);
  fetchUnit.requestFromPC();

  MacroOp mOp = {uopPtr};
  MemoryReadResult memReadResult = {target, RegisterValue(0xFFFF, blockSize),
                                    1};
  span<MemoryReadResult> nextBlock = {&memReadResult, 1};
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(nextBlock));
  ON_CALL(isa, predecode(_, _, _, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(4)));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(memory, clearCompletedReads()).Times(4);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(8);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(4);
  // Tick 4 times to process all 16 bytes of fetched data
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }
  EXPECT_TRUE(fetchUnit.hasHalted());
}

// Tests that fetching a branch instruction (predicted taken) mid block causes a
// branch stall + discards the remaining fetched instructions
TEST_F(PipelineFetchUnitTest, fetchTakenBranchMidBlock) {
  const uint8_t pc = 16;

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));

  MemoryAccessTarget target = {pc, blockSize};
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, requestRead(target, _)).Times(1);

  // Request block from memory
  fetchUnit.updatePC(pc);
  fetchUnit.requestFromPC();

  MacroOp mOp = {uopPtr};
  MemoryReadResult memReadResult = {target, RegisterValue(0xFFFF, blockSize),
                                    1};
  span<MemoryReadResult> nextBlock = {&memReadResult, 1};
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(nextBlock));
  ON_CALL(isa, predecode(_, _, _, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(4)));
  EXPECT_CALL(memory, getCompletedReads()).Times(1);

  // For first tick, process instruction as non-branch
  EXPECT_CALL(memory, clearCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(2);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);
  EXPECT_CALL(*uop, isBranch()).WillOnce(Return(false));
  fetchUnit.tick();

  // For second tick, process a taken branch meaning rest of block is discarded
  // & a new memory block is requested
  EXPECT_CALL(memory, getCompletedReads()).Times(0);
  EXPECT_CALL(memory, clearCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(2);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);
  EXPECT_CALL(*uop, isBranch()).WillOnce(Return(true));
  BranchType bType = BranchType::Unconditional;
  uint64_t knownOff = 304;
  EXPECT_CALL(*uop, getBranchType()).WillOnce(Return(bType));
  EXPECT_CALL(*uop, getKnownOffset()).WillOnce(Return(knownOff));
  BranchPrediction pred = {true, pc + knownOff};
  EXPECT_CALL(predictor, predict(20, bType, knownOff)).WillOnce(Return(pred));
  fetchUnit.tick();

  // Ensure on next tick, predecode is not called
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(memory, clearCompletedReads()).Times(0);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);
  fetchUnit.tick();

  // Make sure on next call to `requestFromPC`, target is address 320
  // (pred.target)
  target = {pred.target, blockSize};
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, requestRead(target, _)).Times(1);
  fetchUnit.requestFromPC();
}

// Tests the functionality of the Loop Buffer
TEST_F(PipelineFetchUnitTest, fetchUnitLoopBuffer) {
  // Register loop boundary
  // Fill loop buffer
  // Have loop buffer supply instructions
  // Make sure `requestFromPC` does nothing
  // Exit from buffer mid supply due to a branch
  // Ensure `requestFromPC` works again
}

}  // namespace pipeline
}  // namespace simeng
