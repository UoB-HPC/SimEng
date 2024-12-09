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

class PipelineFetchUnitTest
    : public testing::TestWithParam<std::pair<uint8_t, uint8_t>> {
 public:
  PipelineFetchUnitTest()
      : output(1, {}),
        linux(config::SimInfo::getConfig()["CPU-Info"]["Special-File-Dir-Path"]
                  .as<std::string>()),
        isa(linux),
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
  const uint8_t insnMinSizeBytes = GetParam().first;
  const uint8_t insnMaxSizeBytes = GetParam().second;
  // TODO make this parameterisable and update all tests accordingly
  const uint8_t blockSize = 16;

  PipelineBuffer<MacroOp> output;
  MockMemoryInterface memory;
  kernel::Linux linux;
  MockArchitecture isa;
  MockBranchPredictor predictor;

  memory::MemoryReadResult fetchBuffer;
  span<memory::MemoryReadResult> completedReads;

  FetchUnit fetchUnit;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
  MockInstruction* uop2;
  std::shared_ptr<Instruction> uopPtr2;
};

// Tests that ticking a fetch unit attempts to predecode from the correct
// program counter and generates output correctly.
TEST_P(PipelineFetchUnitTest, Tick) {
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
TEST_P(PipelineFetchUnitTest, TickStalled) {
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
TEST_P(PipelineFetchUnitTest, FetchUnaligned) {
  MacroOp mOp = {uopPtr};
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  // Min instruction size needs to be more than 1 to set PC correctly for this
  // test
  EXPECT_GT(insnMinSizeBytes, 1);
  uint64_t setPC = (blockSize - insnMinSizeBytes) + 1;
  // Set PC so that there will not be enough data to start decoding
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);
  fetchUnit.updatePC(setPC);
  fetchUnit.tick();

  // Expect a block starting at address 16 to be requested when we fetch again
  EXPECT_CALL(memory,
              requestRead(Field(&memory::MemoryAccessTarget::address, 16), _))
      .Times(1);
  fetchUnit.requestFromPC();

  // Tick again, expecting that decoding will now resume
  memory::MemoryReadResult nextBlockValue = {{16, blockSize}, 0, 1};
  span<memory::MemoryReadResult> nextBlock = {&nextBlockValue, 1};
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
TEST_P(PipelineFetchUnitTest, fetchAligned) {
  const uint8_t pc = 16;

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));

  memory::MemoryAccessTarget target = {pc, blockSize};
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, requestRead(target, _)).Times(1);

  // Request block from Memory
  fetchUnit.updatePC(pc);
  fetchUnit.requestFromPC();

  MacroOp mOp = {uopPtr};
  memory::MemoryReadResult memReadResult = {
      target, RegisterValue(0xFFFF, blockSize), 1};
  span<memory::MemoryReadResult> nextBlock = {&memReadResult, 1};
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
TEST_P(PipelineFetchUnitTest, halted) {
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

  memory::MemoryAccessTarget target = {1008, blockSize};
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(0);
  EXPECT_CALL(memory, requestRead(target, _)).Times(1);
  fetchUnit.requestFromPC();

  MacroOp mOp = {uopPtr};
  memory::MemoryReadResult memReadResult = {
      target, RegisterValue(0xFFFF, blockSize), 1};
  span<memory::MemoryReadResult> nextBlock = {&memReadResult, 1};
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
TEST_P(PipelineFetchUnitTest, fetchTakenBranchMidBlock) {
  const uint8_t pc = 16;

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));

  memory::MemoryAccessTarget target = {pc, blockSize};
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(0);
  EXPECT_CALL(memory, requestRead(target, _)).Times(1);

  // Request block from memory
  fetchUnit.updatePC(pc);
  fetchUnit.requestFromPC();

  MacroOp mOp = {uopPtr};
  memory::MemoryReadResult memReadResult = {
      target, RegisterValue(0xFFFF, blockSize), 1};
  span<memory::MemoryReadResult> nextBlock = {&memReadResult, 1};
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
TEST_P(PipelineFetchUnitTest, supplyFromLoopBuffer) {
  // Set instructions to be fetched from memory
  memory::MemoryReadResult memReadResult = {
      {0x0, blockSize}, RegisterValue(0xFFFF, blockSize), 1};
  span<memory::MemoryReadResult> nextBlock = {&memReadResult, 1};
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
TEST_P(PipelineFetchUnitTest, idleLoopBufferDueToNotTakenBoundary) {
  // Set instructions to be fetched from memory
  memory::MemoryReadResult memReadResultA = {
      {0x0, blockSize}, RegisterValue(0xFFFF, blockSize), 1};
  span<memory::MemoryReadResult> nextBlockA = {&memReadResultA, 1};
  memory::MemoryReadResult memReadResultB = {
      {0x10, blockSize}, RegisterValue(0xFFFF, blockSize), 1};
  span<memory::MemoryReadResult> nextBlockB = {&memReadResultB, 1};
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
  const memory::MemoryAccessTarget target = {0x10, blockSize};
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

// Tests that a min sized instruction held at the end of the fetch buffer is
// allowed to be predecoded in the same cycle as being fetched
TEST_P(PipelineFetchUnitTest, minSizeInstructionAtEndOfBuffer) {
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));
  ON_CALL(isa, getMinInstructionSize()).WillByDefault(Return(insnMinSizeBytes));
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  // Buffer will contain valid min size instruction so predecode returns
  // min bytes read
  MacroOp mOp = {uopPtr};
  ON_CALL(isa, predecode(_, insnMinSizeBytes, 0x10 - insnMinSizeBytes, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(insnMinSizeBytes)));

  // Fetch the data, only min bytes will be copied to fetch buffer. Should allow
  // continuation to predecode
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

  uint64_t setPC = blockSize - insnMinSizeBytes;
  // Fetch a single minimum sized instruction, buffered bytes = 0
  fetchUnit.updatePC(setPC);
  // Tick. Fetch data and predecode
  fetchUnit.tick();

  // Buffer should now be empty as all bytes predecoded
  EXPECT_EQ(fetchUnit.bufferedBytes_, 0);
  EXPECT_EQ(fetchUnit.output_.getTailSlots()[0], mOp);

  // Expect a block starting at address 16 to be requested when we fetch again
  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  EXPECT_CALL(memory,
              requestRead(Field(&memory::MemoryAccessTarget::address, 16), _))
      .Times(1);
  fetchUnit.requestFromPC();

  // Tick again, expecting that decoding will now resume
  MacroOp mOp2 = {uopPtr2};
  memory::MemoryReadResult nextBlockValue = {{16, blockSize}, 0, 1};
  span<memory::MemoryReadResult> nextBlock = {&nextBlockValue, 1};
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(nextBlock));
  ON_CALL(isa, predecode(_, _, _, _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp2), Return(insnMaxSizeBytes)));

  EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
  // Completed reads called again as more data is requested
  EXPECT_CALL(memory, getCompletedReads()).Times(1);
  EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
  // Output of width 1 so only 1 call to predecode
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

  fetchUnit.tick();

  // Initially 0 bytes, 16 bytes added, max bytes predecoded leaving (16 - max)
  // bytes left
  EXPECT_EQ(fetchUnit.bufferedBytes_, 16 - insnMaxSizeBytes);
  EXPECT_EQ(fetchUnit.output_.getTailSlots()[0], mOp2);
}

// Test that invalid min number of bytes held at the end of the buffer is not
// successfully predecoded and that more data is fetched subsequently allowing
// progression as a full instruction is now present in the buffer
TEST_P(PipelineFetchUnitTest, invalidMinBytesAtEndOfBuffer) {
  // This is only relevant if min and max size are different. Otherwise, there
  // won't be any progression as the fetch unit will be caught in an infinite
  // loop
  if (insnMinSizeBytes < insnMaxSizeBytes) {
    ON_CALL(isa, getMaxInstructionSize())
        .WillByDefault(Return(insnMaxSizeBytes));
    ON_CALL(isa, getMinInstructionSize())
        .WillByDefault(Return(insnMinSizeBytes));
    ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

    // Buffer will contain invalid min bytes so predecode returns 0 bytes read
    ON_CALL(isa, predecode(_, insnMinSizeBytes, 0x10 - insnMinSizeBytes, _))
        .WillByDefault(Return(0));

    // getMaxInstructionSize called for second time in assertion
    if (strcmp(SIMENG_BUILD_TYPE, "Release") == 0) {
      EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
    } else {
      EXPECT_CALL(isa, getMaxInstructionSize()).Times(2);
    }
    EXPECT_CALL(memory, getCompletedReads()).Times(1);
    EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
    EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

    uint64_t setPC = blockSize - insnMinSizeBytes;
    // Fetch a single minimum sized instruction, buffered bytes = 0
    fetchUnit.updatePC(setPC);
    // Tick
    fetchUnit.tick();

    // No data consumed
    EXPECT_EQ(fetchUnit.bufferedBytes_, insnMinSizeBytes);
    EXPECT_EQ(fetchUnit.output_.getTailSlots()[0], MacroOp());

    // Expect that memory is requested even though there is data in the buffer
    // as bufferedBytes < maxInstructionSize
    EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
    EXPECT_CALL(memory,
                requestRead(Field(&memory::MemoryAccessTarget::address, 16), _))
        .Times(1);
    fetchUnit.requestFromPC();

    // Tick again expecting buffer to be filled and a word is predecoded
    MacroOp mOp = {uopPtr};
    memory::MemoryReadResult nextBlockValue = {{16, blockSize}, 0, 1};
    span<memory::MemoryReadResult> nextBlock = {&nextBlockValue, 1};
    ON_CALL(memory, getCompletedReads()).WillByDefault(Return(nextBlock));
    ON_CALL(isa, predecode(_, _, _, _))
        .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(insnMaxSizeBytes)));

    EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
    EXPECT_CALL(memory, getCompletedReads()).Times(1);
    EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
    EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

    fetchUnit.tick();

    // Initially min bytes, 16 bytes added, max bytes predecoded
    EXPECT_EQ(fetchUnit.bufferedBytes_,
              (insnMinSizeBytes + 16) - insnMaxSizeBytes);
    EXPECT_EQ(fetchUnit.output_.getTailSlots()[0], mOp);
  }
}

// When min and max instruction sizes are different, ensure progression with
// valid min sized instruction at end of buffer when next read doesn't complete.
TEST_P(PipelineFetchUnitTest, validMinSizeReadsDontComplete) {
  // In the case that min and max are the same, memory is never requested as
  // there is enough data in the buffer. In this case, the test isn't relevant
  if (insnMinSizeBytes < insnMaxSizeBytes) {
    ON_CALL(isa, getMaxInstructionSize())
        .WillByDefault(Return(insnMaxSizeBytes));
    ON_CALL(isa, getMinInstructionSize())
        .WillByDefault(Return(insnMinSizeBytes));
    ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

    // Buffer will contain valid max and min sized instruction, predecode
    // returns max bytes read on first tick
    MacroOp mOp = {uopPtr};
    ON_CALL(isa, predecode(_, insnMaxSizeBytes + insnMinSizeBytes,
                           0x10 - (insnMaxSizeBytes + insnMinSizeBytes), _))
        .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(insnMaxSizeBytes)));

    // Fetch the data, only last max + min bytes from block. Should allow
    // continuation to predecode
    EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
    EXPECT_CALL(memory, getCompletedReads()).Times(1);
    EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
    EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

    uint64_t setPC = blockSize - (insnMaxSizeBytes + insnMinSizeBytes);
    // Fetch a minimum and maximum sized instruction, buffered bytes = 0
    fetchUnit.updatePC(setPC);
    // Tick and predecode max bytes
    fetchUnit.tick();

    // Ensure max bytes consumed
    EXPECT_EQ(fetchUnit.bufferedBytes_, insnMinSizeBytes);
    EXPECT_EQ(fetchUnit.pc_, blockSize - insnMinSizeBytes);
    EXPECT_EQ(fetchUnit.output_.getTailSlots()[0], mOp);

    // Expect that memory is requested even though there is data in the buffer
    // as bufferedBytes < maxInstructionSize
    EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
    EXPECT_CALL(memory,
                requestRead(Field(&memory::MemoryAccessTarget::address, 16), _))
        .Times(1);
    fetchUnit.requestFromPC();

    EXPECT_EQ(fetchUnit.bufferedBytes_, insnMinSizeBytes);
    EXPECT_EQ(fetchUnit.pc_, blockSize - insnMinSizeBytes);

    // Memory doesn't complete reads in next cycle but buffered bytes should be
    // predecoded
    MacroOp mOp2 = {uopPtr2};
    ON_CALL(memory, getCompletedReads())
        .WillByDefault(Return(span<memory::MemoryReadResult>{nullptr, 0}));
    ON_CALL(isa, predecode(_, insnMinSizeBytes, 0x10 - insnMinSizeBytes, _))
        .WillByDefault(DoAll(SetArgReferee<3>(mOp2), Return(insnMinSizeBytes)));

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

    // Ensure min bytes are consumed
    EXPECT_EQ(fetchUnit.bufferedBytes_, 0);
    EXPECT_EQ(fetchUnit.pc_, 16);
    EXPECT_EQ(fetchUnit.output_.getTailSlots()[0], mOp2);
  }
}

// Test that minimum bytes held at the end of the buffer is not successfully
// predecoded and should be re-tried when reads don't complete
TEST_P(PipelineFetchUnitTest, invalidMinBytesreadsDontComplete) {
  // In the case where min and max are the same, predecode will never return 0
  // so the test is only relevent in the case where they are different
  if (insnMinSizeBytes < insnMaxSizeBytes) {
    ON_CALL(isa, getMaxInstructionSize())
        .WillByDefault(Return(insnMaxSizeBytes));
    ON_CALL(isa, getMinInstructionSize())
        .WillByDefault(Return(insnMinSizeBytes));
    ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

    // Buffer will contain invalid min bytes so predecode returns 0 bytes read
    ON_CALL(isa, predecode(_, insnMinSizeBytes, 0x10 - insnMinSizeBytes, _))
        .WillByDefault(Return(0));

    // getMaxInstructionSize called for second time in assertion
    if (strcmp(SIMENG_BUILD_TYPE, "Release") == 0) {
      EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
    } else {
      EXPECT_CALL(isa, getMaxInstructionSize()).Times(2);
    }
    EXPECT_CALL(memory, getCompletedReads()).Times(1);
    EXPECT_CALL(isa, getMinInstructionSize()).Times(1);
    EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

    uint64_t setPC = blockSize - insnMinSizeBytes;
    // Fetch a minimum number of bytes, buffered bytes = 0
    fetchUnit.updatePC(setPC);
    // Tick
    fetchUnit.tick();

    // No data consumed
    EXPECT_EQ(fetchUnit.bufferedBytes_, insnMinSizeBytes);
    EXPECT_EQ(fetchUnit.pc_, blockSize - insnMinSizeBytes);
    EXPECT_EQ(fetchUnit.output_.getTailSlots()[0], MacroOp());

    // Expect that memory is requested even though there is data in the buffer
    // as bufferedBytes < maxInstructionSize
    EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
    EXPECT_CALL(memory,
                requestRead(Field(&memory::MemoryAccessTarget::address, 16), _))
        .Times(1);
    fetchUnit.requestFromPC();

    EXPECT_EQ(fetchUnit.bufferedBytes_, insnMinSizeBytes);
    EXPECT_EQ(fetchUnit.pc_, blockSize - insnMinSizeBytes);

    // Memory doesn't complete reads in next cycle but buffered bytes should
    // attempt to be predecoded
    ON_CALL(memory, getCompletedReads())
        .WillByDefault(Return(span<memory::MemoryReadResult>{nullptr, 0}));
    // Predecode still returns no bytes read
    ON_CALL(isa, predecode(_, insnMinSizeBytes, 0x10 - insnMinSizeBytes, _))
        .WillByDefault(Return(0));

    // getMaxInsnSize called again in assertion
    if (strcmp(SIMENG_BUILD_TYPE, "Release") == 0) {
      EXPECT_CALL(isa, getMaxInstructionSize()).Times(1);
    } else {
      EXPECT_CALL(isa, getMaxInstructionSize()).Times(2);
    }
    EXPECT_CALL(memory, getCompletedReads()).Times(1);
    EXPECT_CALL(isa, getMinInstructionSize()).Times(2);
    EXPECT_CALL(isa, predecode(_, _, _, _)).Times(1);

    // Tick
    fetchUnit.tick();

    // Ensure min bytes are not consumed
    EXPECT_EQ(fetchUnit.bufferedBytes_, insnMinSizeBytes);
    EXPECT_EQ(fetchUnit.pc_, blockSize - insnMinSizeBytes);
    EXPECT_EQ(fetchUnit.output_.getTailSlots()[0], MacroOp());
  }
}

// Test that the Fetch unit is correctly tallying the number of branch
// instructions fetched, and that the getBranchFetchedCount getter function
// returns the correct value
TEST_P(PipelineFetchUnitTest, branchesFetchedCountedIncorrectly) {
  // Set instructions to be fetched from memory
  memory::MemoryReadResult memReadResultA = {
      {0x0, blockSize}, RegisterValue(0xFFFF, blockSize), 1};
  span<memory::MemoryReadResult> nextBlockA = {&memReadResultA, 1};
  memory::MemoryReadResult memReadResultB = {
      {0x10, blockSize}, RegisterValue(0xFFFF, blockSize), 1};
  span<memory::MemoryReadResult> nextBlockB = {&memReadResultB, 1};
  EXPECT_CALL(memory, getCompletedReads()).WillRepeatedly(Return(nextBlockA));

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(insnMaxSizeBytes));

  // Set the instructions to be returned from predecode
  MacroOp mOp2 = {uopPtr2};
  ON_CALL(isa, predecode(_, _, Gt(0x8), _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp2), Return(4)));
  ON_CALL(*uop2, isBranch()).WillByDefault(Return(true));
  MacroOp mOp = {uopPtr};
  ON_CALL(isa, predecode(_, _, Lt(0xC), _))
      .WillByDefault(DoAll(SetArgReferee<3>(mOp), Return(4)));
  ON_CALL(*uop, isBranch()).WillByDefault(Return(false));
  EXPECT_CALL(predictor, predict(_, _, _))
      .WillOnce(Return(BranchPrediction({true, 0x0})));

  // Fetch instructions from data block -- one branch instruction
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }

  // Confirm that the correct number of fetched branches has been recorded by
  // the Fetch Unit
  EXPECT_EQ(fetchUnit.getBranchFetchedCount(), 1);

  // Fetch the next block of instructions from memory and change the expected
  // outcome of the branch predictor
  fetchUnit.requestFromPC();
  EXPECT_CALL(predictor, predict(_, _, _))
      .WillRepeatedly(Return(BranchPrediction({false, 0x0})));

  // Fetch instructions from data block -- one branch instruction
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }

  // Confirm that the correct number of fetched branches has been recorded by
  // the Fetch Unit
  EXPECT_EQ(fetchUnit.getBranchFetchedCount(), 2);

  const memory::MemoryAccessTarget target = {0x10, blockSize};
  EXPECT_CALL(memory, getCompletedReads()).WillRepeatedly(Return(nextBlockB));
  EXPECT_CALL(memory, requestRead(target, _)).Times(1);

  // Fetch instructions from data block -- four branch instructions
  fetchUnit.requestFromPC();
  for (int i = 0; i < 4; i++) {
    fetchUnit.tick();
  }

  // Confirm that the correct number of fetched branches has been recorded by
  // the Fetch Unit
  EXPECT_EQ(fetchUnit.getBranchFetchedCount(), 6);
}

INSTANTIATE_TEST_SUITE_P(PipelineFetchUnitTests, PipelineFetchUnitTest,
                         ::testing::Values(std::pair(2, 4), std::pair(4, 4)));

}  // namespace pipeline
}  // namespace simeng
