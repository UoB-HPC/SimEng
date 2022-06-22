#include "../MockArchitecture.hh"
#include "../MockBranchPredictor.hh"
#include "../MockInstruction.hh"
#include "../MockMemoryInterface.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/control.hh"
#include "simeng/pipeline/FetchUnit.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/trace.hh"

bool tracing;
bool enableTrace;
bool probing;
bool enableProbe;
bool enableFocus;
bool recordEvents;
uint64_t trace_cycle;
uint64_t traceId;
std::map<uint64_t, simeng::Trace*> traceMap;
std::list<simeng::Trace*> probeList;

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
        fetchUnit(output, memory, 1024, 0, 16, isa, predictor),
        uop(new MockInstruction),
        uopPtr(uop) {
    uopPtr->setInstructionAddress(0);
  }

 protected:
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

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(4));

  // Anticipate testing instruction type; return true for branch
  ON_CALL(*uop, isBranch()).WillByDefault(Return(true));

  // Set the output parameter to a 1-wide macro-op
  EXPECT_CALL(isa, predecode(_, _, 0, _, _))
      .WillOnce(DoAll(SetArgReferee<3>(macroOp), Return(4)));

  BranchPrediction prediction = {0, true};
  EXPECT_CALL(predictor, predict(0, BranchType::Conditional, 0))
      .WillOnce(Return(prediction));

  fetchUnit.tick();

  // Verify that the macro-op was pushed to the output
  EXPECT_EQ(output.getTailSlots()[0].size(), 1);
}

// Tests that ticking a fetch unit does nothing if the output has stalled
TEST_F(PipelineFetchUnitTest, TickStalled) {
  output.stall(true);

  // Anticipate testing instruction type; return true for branch
  ON_CALL(*uop, isBranch()).WillByDefault(Return(true));

  EXPECT_CALL(isa, predecode(_, _, _, _, _)).Times(0);

  EXPECT_CALL(predictor, predict(_, _, _)).Times(0);

  fetchUnit.tick();

  // Verify that nothing was pushed to the output
  EXPECT_EQ(output.getTailSlots()[0].size(), 0);
}

// Tests that the fetch unit will handle instructions that straddle fetch block
// boundaries by automatically requesting the next block of data.
TEST_F(PipelineFetchUnitTest, FetchUnaligned) {
  MacroOp macroOp = {uopPtr};
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(4));
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  // Set PC to 14, so there will not be enough data to start decoding
  EXPECT_CALL(isa, predecode(_, _, _, _, _)).Times(0);
  fetchUnit.updatePC(14);
  fetchUnit.tick();

  // Expect a block starting at address 16 to be requested when we fetch again
  EXPECT_CALL(memory, requestRead(Field(&MemoryAccessTarget::address, 16), _))
      .Times(1);
  fetchUnit.requestFromPC();

  // Tick again, expecting that decoding will now resume
  MemoryReadResult nextBlockValue = {{16, 16}, 0, 1};
  span<MemoryReadResult> nextBlock = {&nextBlockValue, 1};
  EXPECT_CALL(memory, getCompletedReads()).WillOnce(Return(nextBlock));
  EXPECT_CALL(isa, predecode(_, _, _, _, _))
      .WillOnce(DoAll(SetArgReferee<3>(macroOp), Return(4)));
  fetchUnit.tick();
}

}  // namespace pipeline
}  // namespace simeng
