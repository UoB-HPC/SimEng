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
using ::testing::AllOf;
using ::testing::AnyNumber;
using ::testing::AnyOf;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Field;
using ::testing::Gt;
using ::testing::Lt;
using ::testing::Ne;
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
        uopPtr(uop),
        uop2(new MockInstruction),
        uopPtr2(uop2) {
    uopPtr->setInstructionAddress(0);
  }

 protected:
  const uint8_t insnMaxSizeBytes = 4;
  const uint8_t insnMinSizeBytes = 2;
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
  MockInstruction* uop2;
  std::shared_ptr<Instruction> uopPtr2;
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
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  // Set PC to 15, so there will not be enough data to start decoding
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);
  fetchUnit.updatePC(15);
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
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(4);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(4);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(4);

  // Tick 4 times to process all 16 bytes of fetched data
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }
  // Tick a 5th time to ensure all buffered bytes have been used
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);
  fetchUnit.tick();
}

// Tests that a properly aligned PC (to the fetch block boundary) is correctly
// fetched
TEST_F(PipelineFetchUnitTest, fetchAligned) {
  const uint8_t pc = 16;

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));

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
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(4);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(4);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(4);

  // Tick 4 times to process all 16 bytes of fetched data
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }
  // Tick a 5th time to ensure all buffered bytes have been used
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(memory, clearCompletedReads()).Times(0);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);
  fetchUnit.tick();
}

// Tests that halting functionality triggers correctly
TEST_F(PipelineFetchUnitTest, halted) {
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));
  EXPECT_FALSE(fetchUnit.hasHalted());
  fetchUnit.tick();
  EXPECT_FALSE(fetchUnit.hasHalted());

  // Test PC >= programByteLength triggers halting
  fetchUnit.updatePC(1024);
  EXPECT_TRUE(fetchUnit.hasHalted());

  // Test PC being incremented to >= programByteLength triggers halting
  fetchUnit.updatePC(1008);
  EXPECT_FALSE(fetchUnit.hasHalted());

  MemoryAccessTarget target = {1008, blockSize};
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(0);
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
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(4);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(4);
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
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));

  MemoryAccessTarget target = {pc, blockSize};
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(0);
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
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);
  EXPECT_CALL(*uop, isBranch()).WillOnce(Return(false));
  fetchUnit.tick();

  // For second tick, process a taken branch meaning rest of block is discarded
  // & a new memory block is requested
  EXPECT_CALL(memory, getCompletedReads()).Times(0);
  EXPECT_CALL(memory, clearCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
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
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);
  fetchUnit.tick();

  // Make sure on next call to `requestFromPC`, target is address 320
  // (pred.target)
  target = {pred.target, blockSize};
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(0);
  EXPECT_CALL(memory, requestRead(target, _)).Times(1);
  fetchUnit.requestFromPC();
}

// Tests the functionality of the supplying from the Loop Buffer
TEST_F(PipelineFetchUnitTest, supplyFromLoopBuffer) {
  // Set instructions to be fetched from memory
  MemoryReadResult memReadResult = {
      {0x0, blockSize}, RegisterValue(0xFFFF, blockSize), 1};
  span<MemoryReadResult> nextBlock = {&memReadResult, 1};
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(nextBlock));

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));

  // Register loop boundary
  fetchUnit.registerLoopBoundary(0xC);

  // Set the instructions, within the loop body, to be returned from predecode
  MacroOp mOp2 = {uopPtr2};
  ON_CALL(isa, predecode(_, _, 0xC, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp2), Return(4)));
  ON_CALL(*uop2, isBranch()).WillByDefault(Return(true));

  MacroOp mOp = {uopPtr};
  ON_CALL(isa, predecode(_, _, Ne(0xC), _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(4)));
  ON_CALL(*uop, isBranch()).WillByDefault(Return(false));

  // Set the expectation from the predictor to be true so a loop body will
  // be detected
  ON_CALL(predictor, predict(_, _, _))
      .WillByDefault(Return(BranchPrediction({true, 0x0})));

  // Set Loop Buffer state to be LoopBufferState::FILLING
  // Tick 4 times to process all 16 bytes of fetched data
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }

  // Fetch the next block of instructions from memory
  fetchUnit.requestFromPC();

  // Fill Loop Buffer and set its state to be LoopBufferState::SUPPLYING
  // Tick 4 times to process all 16 bytes of fetched data
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }

  // Whilst the Loop Buffer state is LoopBufferState::SUPPLYING, the request
  // read should never be called
  EXPECT_CALL(memory, requestRead(_, _)).Times(0);
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(0);
  EXPECT_CALL(memory, getCompletedReads()).Times(0);
  fetchUnit.requestFromPC();

  // Empty output buffer and ensure the correct instructions are supplied from
  // the Loop Buffer
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp);
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp);
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp);
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp2);

  // Flush the Loop Buffer and ensure correct instructions are fetched from
  // memory
  fetchUnit.flushLoopBuffer();
  fetchUnit.updatePC(0x0);
  EXPECT_CALL(memory, requestRead(_, _)).Times(AtLeast(1));
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(AtLeast(1));
  EXPECT_CALL(memory, getCompletedReads()).Times(AtLeast(1));
  fetchUnit.requestFromPC();
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp);
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp);
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp);
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp2);
}

// Tests the functionality of idling the supply to the Loop Buffer one of not
// taken branch at the loopBoundaryAddress_
TEST_F(PipelineFetchUnitTest, idleLoopBufferDueToNotTakenBoundary) {
  // Set instructions to be fetched from memory
  MemoryReadResult memReadResultA = {
      {0x0, blockSize}, RegisterValue(0xFFFF, blockSize), 1};
  span<MemoryReadResult> nextBlockA = {&memReadResultA, 1};
  MemoryReadResult memReadResultB = {
      {0x10, blockSize}, RegisterValue(0xFFFF, blockSize), 1};
  span<MemoryReadResult> nextBlockB = {&memReadResultB, 1};
  EXPECT_CALL(memory, getCompletedReads()).WillRepeatedly(Return(nextBlockA));

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));

  // Register loop boundary
  fetchUnit.registerLoopBoundary(0xC);

  // Set the instructions, within the loop body, to be returned from predecode
  MacroOp mOp2 = {uopPtr2};
  ON_CALL(isa, predecode(_, _, Gt(0x8), _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp2), Return(4)));
  ON_CALL(*uop2, isBranch()).WillByDefault(Return(true));

  MacroOp mOp = {uopPtr};
  ON_CALL(isa, predecode(_, _, Lt(0xC), _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(4)));
  ON_CALL(*uop, isBranch()).WillByDefault(Return(false));

  // Set the first expectation from the predictor to be true so a loop body will
  // be detected
  EXPECT_CALL(predictor, predict(_, _, _))
      .WillOnce(Return(BranchPrediction({true, 0x0})));

  // Set Loop Buffer state to be LoopBufferState::FILLING
  // Tick 4 times to process all 16 bytes of fetched data
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }

  // Fetch the next block of instructions from memory and change the expected
  // outcome of the branch predictor
  fetchUnit.requestFromPC();
  EXPECT_CALL(predictor, predict(_, _, _))
      .WillRepeatedly(Return(BranchPrediction({false, 0x0})));

  // Attempt to fill Loop Buffer but prevent it on a not taken outcome at the
  // loopBoundaryAddress_ branch
  // Tick 4 times to process all 16 bytes of fetched data
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }

  // Set the expectation for the next block to be fetched after the Loop Buffer
  // state has been reset
  const MemoryAccessTarget target = {0x10, blockSize};
  EXPECT_CALL(memory, getCompletedReads()).WillRepeatedly(Return(nextBlockB));
  EXPECT_CALL(memory, requestRead(target, _)).Times(1);

  // Fetch the next block of instructions from memory
  fetchUnit.requestFromPC();

  // Empty output buffer and ensure the correct instructions are fetched from
  // memory
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp2);
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp2);
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp2);
  output.fill({});
  fetchUnit.tick();
  EXPECT_EQ(output.getTailSlots()[0], mOp2);
}

// Tests that a compressed instruction held at the end of the fetch buffer is
// allowed to be predecoded in the same cycle as being fetched
TEST_F(PipelineFetchUnitTest, compressedInstructionAtEndOfBuffer) {
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  // Buffer will contain valid compressed instruction so predecode returns
  // 2 bytes read
  MacroOp mOp = {uopPtr};
  ON_CALL(isa, predecode(_, 2, 0xE, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(2)));

  // Fetch the data, only 2 bytes will be copied to fetch buffer. Should allow
  // continuation to predecode
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

  // Set PC to 14, buffered bytes = 0
  fetchUnit.updatePC(14);
  // Tick. Fetch data and predecode
  fetchUnit.tick();

  // Buffer should now be empty as all bytes predecoded
  EXPECT_EQ(fetchUnit.bufferedBytes_, 0);

  // Expect a block starting at address 16 to be requested when we fetch again
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, requestRead(Field(&MemoryAccessTarget::address, 16), _))
      .Times(1);
  fetchUnit.requestFromPC();

  // Tick again, expecting that decoding will now resume
  MemoryReadResult nextBlockValue = {{16, blockSize}, 0, 1};
  span<MemoryReadResult> nextBlock = {&nextBlockValue, 1};
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(nextBlock));
  ON_CALL(isa, predecode(_, _, _, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(4)));

  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  // Completed reads called again as more data is requested
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  // Output of width 1 so only 1 call to predecode
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

  fetchUnit.tick();

  // Initially 0 bytes, 16 bytes added, 4 bytes predecoded leaving 12 bytes left
  EXPECT_EQ(fetchUnit.bufferedBytes_, 12);
}

// Test that invalid half byte held at the end of the buffer is not successfully
// predecoded and that more data is fetched subsequently allowing progression
TEST_F(PipelineFetchUnitTest, invalidHalfWordAtEndOfBuffer) {
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  // Buffer will contain invalid 2 bytes so predecode returns 0 bytes read
  MacroOp mOp = {uopPtr};
  ON_CALL(isa, predecode(_, 2, 0xE, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(0)));

  // getMaxInstructionSize called for second time in assertion
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(2);
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

  // Set PC to 14, buffered bytes = 0
  fetchUnit.updatePC(14);
  // Tick
  fetchUnit.tick();

  // No data consumed
  EXPECT_EQ(fetchUnit.bufferedBytes_, 2);

  // Expect that memory is requested even though there is data in the buffer as
  // bufferedBytes < maxInstructionSize
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, requestRead(Field(&MemoryAccessTarget::address, 16), _))
      .Times(1);
  fetchUnit.requestFromPC();

  // Tick again expecting buffer to be filled and a word is predecoded
  MemoryReadResult nextBlockValue = {{16, blockSize}, 0, 1};
  span<MemoryReadResult> nextBlock = {&nextBlockValue, 1};
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(nextBlock));
  ON_CALL(isa, predecode(_, _, _, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(4)));

  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

  fetchUnit.tick();

  // Initially 2 bytes, 16 bytes added, 4 bytes predecoded leaving 14 bytes left
  EXPECT_EQ(fetchUnit.bufferedBytes_, 14);
}

// Ensure progression with valid 2 bytes at end of buffer when next read doesn't
// complete
TEST_F(PipelineFetchUnitTest, validCompressed_ReadsDontComplete) {
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  // Buffer will contain valid 6 bytes so predecode returns 4 bytes read on
  // first tick
  MacroOp mOp = {uopPtr};
  ON_CALL(isa, predecode(_, 6, 0xA, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(4)));

  // Fetch the data, only last 6 bytes from block. Should allow continuation to
  // predecode
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

  // Set PC to 10, buffered bytes = 0
  fetchUnit.updatePC(10);
  // Tick and predecode 4 bytes
  fetchUnit.tick();

  // Ensure 4 bytes consumed
  EXPECT_EQ(fetchUnit.bufferedBytes_, 2);
  EXPECT_EQ(fetchUnit.pc_, 14);

  // Expect that memory is requested even though there is data in the buffer as
  // bufferedBytes < maxInstructionSize
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, requestRead(Field(&MemoryAccessTarget::address, 16), _))
      .Times(1);
  fetchUnit.requestFromPC();

  EXPECT_EQ(fetchUnit.bufferedBytes_, 2);
  EXPECT_EQ(fetchUnit.pc_, 14);

  // Memory doesn't complete reads in next cycle but buffered bytes should be
  // predecoded
  ON_CALL(memory, getCompletedReads())
      .WillByDefault(Return(span<MemoryReadResult>{nullptr, 0}));
  ON_CALL(isa, predecode(_, 2, 0xE, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(2)));

  // Path through fetch as follows:
  // More data required as bufferedBytes_ < maxInsnSize so getCompletedReads
  // Doesn't complete so buffer doesn't get added to
  // Buffer still has some valid data so predecode should be called

  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(2);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

  // Tick
  fetchUnit.tick();

  // Ensure 2 bytes are consumed
  EXPECT_EQ(fetchUnit.bufferedBytes_, 0);
  EXPECT_EQ(fetchUnit.pc_, 16);
}

// If invalid 2 bytes and no load then repeated calls to
// predecode
// Should there be a way to prevent repeated predecode of the same invalid byte

// TODO is this correct/desired behaviour????
// Test that invalid half byte held at the end of the buffer is not successfully
// predecoded and should be retried when reads don't complete
TEST_F(PipelineFetchUnitTest, invalidHalfWord_readsDontComplete) {
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  // Buffer will contain invalid 2 bytes so predecode returns 0 bytes read
  MacroOp mOp = {uopPtr};
  ON_CALL(isa, predecode(_, 2, 0xE, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(0)));

  // getMaxInstructionSize called for second time in assertion
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(2);
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

  // Set PC to 14, buffered bytes = 0
  fetchUnit.updatePC(14);
  // Tick
  fetchUnit.tick();

  // No data consumed
  EXPECT_EQ(fetchUnit.bufferedBytes_, 2);
  EXPECT_EQ(fetchUnit.pc_, 14);

  // Expect that memory is requested even though there is data in the buffer as
  // bufferedBytes < maxInstructionSize
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, requestRead(Field(&MemoryAccessTarget::address, 16), _))
      .Times(1);
  fetchUnit.requestFromPC();

  EXPECT_EQ(fetchUnit.bufferedBytes_, 2);
  EXPECT_EQ(fetchUnit.pc_, 14);

  // Memory doesn't complete reads in next cycle but buffered bytes should
  // attempt to be predecoded
  ON_CALL(memory, getCompletedReads())
      .WillByDefault(Return(span<MemoryReadResult>{nullptr, 0}));
  // Predecode still returns no bytes read
  ON_CALL(isa, predecode(_, 2, 0xE, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(0)));

  // getMaxInsnSize called again in assertion
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(2);
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(2);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

  // Tick
  fetchUnit.tick();

  // Ensure 2 bytes are consumed
  EXPECT_EQ(fetchUnit.bufferedBytes_, 2);
  EXPECT_EQ(fetchUnit.pc_, 14);
}

}  // namespace pipeline
}  // namespace simeng
