#include "../MockArchitecture.hh"
#include "../MockBranchPredictor.hh"
#include "../MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/memory/SimpleMem.hh"
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
        memory(std::make_shared<memory::SimpleMem>(1024)),
        mmu(std::make_shared<memory::MMU>(memory, latency, fn, tid)),
        fetchUnit(output, mmu, 16, isa, predictor),
        uop(new MockInstruction),
        uopPtr(uop) {
    uopPtr->setInstructionAddress(0);
    fetchUnit.setProgramLength(1024);
    fetchUnit.updatePC(0);
  }

 protected:
  PipelineBuffer<MacroOp> output;
  MockArchitecture isa;
  MockBranchPredictor predictor;

  memory::MemoryReadResult fetchBuffer;
  span<memory::MemoryReadResult> completedReads;

  const uint64_t latency = 0;
  const uint64_t tid = 0;
  VAddrTranslator fn = [](uint64_t vaddr, uint64_t pid) -> uint64_t {
    return vaddr;
  };
  std::shared_ptr<memory::SimpleMem> memory;
  std::shared_ptr<memory::MMU> mmu;

  FetchUnit fetchUnit;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
};

// Tests that ticking a fetch unit attempts to predecode from the correct
// program counter and generates output correctly.
TEST_F(PipelineFetchUnitTest, Tick) {
  MacroOp macroOp = {uopPtr};

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(4));

  // Set the output parameter to a 1-wide macro-op
  EXPECT_CALL(isa, predecode(_, _, 0, _))
      .WillOnce(DoAll(SetArgReferee<3>(macroOp), Return(4)));

  // Prefetch instructions from memory
  mmu->requestInstrRead({0, 16});

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
  MacroOp macroOp = {uopPtr};
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(4));
  mmu->clearCompletedIntrReads();

  // Set PC to 14, so there will not be enough data to start decoding
  EXPECT_CALL(isa, predecode(_, _, _, _)).Times(0);
  fetchUnit.setProgramLength(1024);
  fetchUnit.updatePC(14);
  fetchUnit.requestFromPC();
  fetchUnit.tick();
  // Fetch ocurred on block 0->16, with bytes 14-16 being buffered. Hence, no
  // decode
  EXPECT_EQ(mmu->getCompletedInstrReads().size(), 1);
  EXPECT_EQ(mmu->getCompletedInstrReads()[0].target.address, 0);
  EXPECT_EQ(mmu->getCompletedInstrReads()[0].data.size(), 16);

  // Expect a block starting at address 16 to be requested when we fetch again
  fetchUnit.requestFromPC();
  // Ensure that a block starting at address 16, of size 16-bytes, was fetched
  EXPECT_EQ(mmu->getCompletedInstrReads()[1].target.address, 16);
  EXPECT_EQ(mmu->getCompletedInstrReads()[1].data.size(), 16);

  // Tick again, expecting that decoding will now resume
  memory::MemoryReadResult nextBlockValue = {{16, 16}, 0, 1};
  span<memory::MemoryReadResult> nextBlock = {&nextBlockValue, 1};
  EXPECT_CALL(isa, predecode(_, _, _, _))
      .WillOnce(DoAll(SetArgReferee<3>(macroOp), Return(4)));
  fetchUnit.tick();
}

}  // namespace pipeline
}  // namespace simeng
