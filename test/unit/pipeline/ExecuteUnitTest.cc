#include "../MockBranchPredictor.hh"
#include "../MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/pipeline/ExecuteUnit.hh"

namespace simeng {
namespace pipeline {

using ::testing::AtLeast;
using ::testing::ElementsAre;
using ::testing::Invoke;
using ::testing::IsEmpty;
using ::testing::Property;
using ::testing::Return;

class MockExecutionHandlers {
 public:
  MOCK_METHOD2(forwardOperands,
               void(const span<Register>, const span<RegisterValue>));
  MOCK_METHOD1(raiseException, void(std::shared_ptr<Instruction> instruction));
};

class PipelineExecuteUnitTest : public testing::Test {
 public:
  PipelineExecuteUnitTest()
      : input(1, nullptr),
        output(1, nullptr),
        executeUnit(
            input, output,
            [this](auto regs, auto values) {
              executionHandlers.forwardOperands(regs, values);
            },
            [](auto uop) {}, [](auto uop) {},
            [this](auto instruction) {
              executionHandlers.raiseException(instruction);
            },
            true, {3, 4, 5}),
        uop(new MockInstruction),
        secondUop(new MockInstruction),
        thirdUop(new MockInstruction),
        uopPtr(uop),
        secondUopPtr(secondUop),
        thirdUopPtr(thirdUop) {}

 protected:
  PipelineBuffer<std::shared_ptr<Instruction>> input;
  PipelineBuffer<std::shared_ptr<Instruction>> output;
  MockBranchPredictor predictor;
  MockExecutionHandlers executionHandlers;

  ExecuteUnit executeUnit;

  MockInstruction* uop;
  MockInstruction* secondUop;
  MockInstruction* thirdUop;

  std::shared_ptr<Instruction> uopPtr;
  std::shared_ptr<Instruction> secondUopPtr;
  std::shared_ptr<Instruction> thirdUopPtr;
};

// Tests that the execution unit processes nothing if no instruction is present
TEST_F(PipelineExecuteUnitTest, TickEmpty) {
  EXPECT_TRUE(executeUnit.isEmpty());
  executeUnit.tick();

  EXPECT_TRUE(executeUnit.isEmpty());
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
}

// Tests that a flushed instruction is removed from the input buffer and not
// processed through the EU
TEST_F(PipelineExecuteUnitTest, flushedInputInsn) {
  input.getHeadSlots()[0] = uopPtr;

  // Setup instruction
  uopPtr->setFlushed();
  ON_CALL(*uop, canExecute()).WillByDefault(Return(true));

  executeUnit.tick();

  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  EXPECT_EQ(executeUnit.getCycles(), 0);
}

// Tests that the execution unit executes an instruction and forwards the
// results
TEST_F(PipelineExecuteUnitTest, Execute) {
  input.getHeadSlots()[0] = uopPtr;

  ON_CALL(*uop, canExecute()).WillByDefault(Return(true));
  EXPECT_CALL(*uop, execute()).Times(1);

  std::vector<Register> registers = {{0, 1}};
  std::vector<RegisterValue> values = {RegisterValue(1, 4)};
  // Check that the results/registers are retrieved
  EXPECT_CALL(*uop, getResults())
      .WillOnce(Return(span<RegisterValue>(values.data(), values.size())));
  EXPECT_CALL(*uop, getDestinationRegisters())
      .WillOnce(Return(span<Register>(registers.data(), registers.size())));

  // Check that the results/registers are forwarded
  EXPECT_CALL(
      executionHandlers,
      forwardOperands(ElementsAre(registers[0]),
                      ElementsAre(Property(&RegisterValue::get<uint32_t>, 1))))
      .Times(1);

  executeUnit.tick();

  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
}

TEST_F(PipelineExecuteUnitTest, ExecuteBranch) {
  input.getHeadSlots()[0] = uopPtr;

  ON_CALL(*uop, canExecute()).WillByDefault(Return(true));
  // Anticipate testing instruction type; return true for branch
  ON_CALL(*uop, isBranch()).WillByDefault(Return(true));
  // Return branch type as unconditional by default
  ON_CALL(*uop, getBranchType())
      .WillByDefault(Return(BranchType::Unconditional));

  bool taken = true;
  uint64_t pc = 1;
  const uint64_t insnAddress = 2;

  uop->setInstructionAddress(insnAddress);
  uop->setBranchPrediction({taken, pc});

  EXPECT_CALL(*uop, execute()).WillOnce(Invoke([&]() {
    uop->setExecuted(true);
    uop->setBranchResults(taken, pc);
  }));

  // Check that empty forwarding call is made
  EXPECT_CALL(executionHandlers, forwardOperands(IsEmpty(), IsEmpty()))
      .Times(1);

  executeUnit.tick();

  EXPECT_EQ(uopPtr->wasBranchMispredicted(), false);
  EXPECT_EQ(uopPtr->wasBranchTaken(), taken);

  EXPECT_EQ(executeUnit.shouldFlush(), false);
  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
}

// Test that an instruction that already encountered an exception will raise it
// without executing
TEST_F(PipelineExecuteUnitTest, ExceptionDoesNotExecute) {
  input.getHeadSlots()[0] = uopPtr;

  uop->setExceptionEncountered(true);

  ON_CALL(*uop, canExecute()).WillByDefault(Return(true));
  EXPECT_CALL(*uop, execute()).Times(0);

  EXPECT_CALL(executionHandlers,
              raiseException(Property(&std::shared_ptr<Instruction>::get, uop)))
      .Times(1);

  executeUnit.tick();
}

// Test that an exception-generating execution will raise an exception
TEST_F(PipelineExecuteUnitTest, ExecutionException) {
  input.getHeadSlots()[0] = uopPtr;

  ON_CALL(*uop, canExecute()).WillByDefault(Return(true));
  EXPECT_CALL(*uop, execute()).WillOnce(Invoke([&]() {
    uop->setExecuted(true);
    uop->setExceptionEncountered(true);
  }));

  EXPECT_CALL(executionHandlers,
              raiseException(Property(&std::shared_ptr<Instruction>::get, uop)))
      .Times(1);

  executeUnit.tick();
}

// Test that pipeline stalling functions correctly by stalling the unit during
// processing
TEST_F(PipelineExecuteUnitTest, PipelineStall) {
  input.getHeadSlots()[0] = uopPtr;

  uop->setLatency(5);
  uop->setStallCycles(5);

  ON_CALL(*uop, canExecute()).WillByDefault(Return(true));
  EXPECT_CALL(*uop, execute()).Times(1);
  EXPECT_CALL(*secondUop, execute()).Times(0);

  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  input.getHeadSlots()[0] = secondUopPtr;
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0].get(), secondUop);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0].get(), secondUop);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0].get(), secondUop);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
}

// Test that operation stalling functions correctly by stalling similar
// operations within the same unit
TEST_F(PipelineExecuteUnitTest, OperationStall) {
  input.getHeadSlots()[0] = uopPtr;

  uop->setLatency(5);
  uop->setStallCycles(5);
  ON_CALL(*uop, getGroup()).WillByDefault(Return(3));
  ON_CALL(*uop, canExecute()).WillByDefault(Return(true));
  ON_CALL(*secondUop, getGroup()).WillByDefault(Return(4));
  ON_CALL(*secondUop, canExecute()).WillByDefault(Return(true));
  ON_CALL(*thirdUop, getGroup()).WillByDefault(Return(2));
  ON_CALL(*thirdUop, canExecute()).WillByDefault(Return(true));

  EXPECT_CALL(*uop, execute()).Times(1);
  EXPECT_CALL(*secondUop, execute()).Times(1);
  EXPECT_CALL(*thirdUop, execute()).Times(1);

  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  input.getHeadSlots()[0] = secondUopPtr;
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  input.getHeadSlots()[0] = thirdUopPtr;
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0].get(), thirdUop);
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0].get(), secondUop);
}

// Test that a mispredicted branch instruction is properly handled
TEST_F(PipelineExecuteUnitTest, mispredictedBranch) {
  input.getHeadSlots()[0] = uopPtr;

  ON_CALL(*uop, canExecute()).WillByDefault(Return(true));
  // Anticipate testing instruction type; return true for branch
  ON_CALL(*uop, isBranch()).WillByDefault(Return(true));
  // Return branch type as unconditional by default
  ON_CALL(*uop, getBranchType()).WillByDefault(Return(BranchType::Conditional));

  const bool takenPred = false;
  const bool taken = true;
  const uint64_t pc = 4;
  const uint64_t insnAddress = 16;
  const uint64_t insnID = 5;

  uop->setInstructionAddress(insnAddress);
  uop->setInstructionId(insnID);
  uop->setBranchPrediction({takenPred, insnAddress + 4});

  EXPECT_CALL(*uop, execute()).WillOnce(Invoke([&]() {
    uop->setExecuted(true);
    uop->setBranchResults(taken, pc);
  }));

  // Check that empty forwarding call is made
  EXPECT_CALL(executionHandlers, forwardOperands(IsEmpty(), IsEmpty()))
      .Times(1);

  executeUnit.tick();

  EXPECT_EQ(uopPtr->wasBranchMispredicted(), true);
  EXPECT_EQ(uopPtr->wasBranchTaken(), taken);

  EXPECT_EQ(executeUnit.shouldFlush(), true);
  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
  EXPECT_EQ(executeUnit.getFlushAddress(), pc);
  EXPECT_EQ(executeUnit.getFlushInsnId(), insnID);
}

// Test that the flushing mechansim works correctly via purgeFlushed()
TEST_F(PipelineExecuteUnitTest, purgeFlushed) {
  input.getHeadSlots()[0] = uopPtr;

  uop->setLatency(5);
  uop->setStallCycles(5);
  // Set up instructions so that only one is in the EU pipeline at a time
  ON_CALL(*uop, getGroup()).WillByDefault(Return(3));
  ON_CALL(*uop, canExecute()).WillByDefault(Return(true));
  ON_CALL(*secondUop, getGroup()).WillByDefault(Return(4));
  ON_CALL(*secondUop, canExecute()).WillByDefault(Return(true));
  ON_CALL(*thirdUop, getGroup()).WillByDefault(Return(5));
  ON_CALL(*thirdUop, canExecute()).WillByDefault(Return(true));

  EXPECT_CALL(*uop, execute()).Times(0);
  EXPECT_CALL(*secondUop, execute()).Times(0);
  EXPECT_CALL(*thirdUop, execute()).Times(1);

  // Stage all three instructions in EU pipeline
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  input.getHeadSlots()[0] = secondUopPtr;
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  input.getHeadSlots()[0] = thirdUopPtr;
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);

  // Flush first two instructions
  uopPtr->setFlushed();
  secondUopPtr->setFlushed();
  executeUnit.purgeFlushed();

  // Ensure non-flushed instruction progresses through the pipeline
  executeUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0].get(), thirdUop);
  EXPECT_TRUE(executeUnit.isEmpty());
}

}  // namespace pipeline
}  // namespace simeng
