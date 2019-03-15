#include "../MockBranchPredictor.hh"
#include "../MockInstruction.hh"
#include "inorder/ExecuteUnit.hh"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace simeng {
namespace inorder {

using ::testing::AtLeast;
using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::Property;
using ::testing::Return;

class MockForwardOperands {
 public:
  MOCK_METHOD2(forwardOperands,
               void(const span<Register>, const span<RegisterValue>));
};

class InOrderExecuteUnitTest : public testing::Test {
 public:
  InOrderExecuteUnitTest()
      : input(1, nullptr),
        output(1, nullptr),
        executeUnit(
            input, output,
            [this](auto regs, auto values) {
              forwardOperands.forwardOperands(regs, values);
            },
            predictor, nullptr),
        uop(new MockInstruction),
        uopPtr(uop) {}

 protected:
  PipelineBuffer<std::shared_ptr<Instruction>> input;
  PipelineBuffer<std::shared_ptr<Instruction>> output;
  MockBranchPredictor predictor;
  MockForwardOperands forwardOperands;

  ExecuteUnit executeUnit;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
};

// Tests that the execution unit processes nothing if no instruction is present
TEST_F(InOrderExecuteUnitTest, TickEmpty) {
  // Check that an empty operand forwarding call is made
  EXPECT_CALL(forwardOperands, forwardOperands(IsEmpty(), IsEmpty())).Times(1);

  executeUnit.tick();

  EXPECT_EQ(output.getTailSlots()[0], nullptr);
}

// Tests that the execution unit executes an instruction and forwards the
// results
TEST_F(InOrderExecuteUnitTest, Execute) {
  input.getHeadSlots()[0] = uopPtr;

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
      forwardOperands,
      forwardOperands(ElementsAre(registers[0]),
                      ElementsAre(Property(&RegisterValue::get<uint32_t>, 1))))
      .Times(1);

  executeUnit.tick();

  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
}

TEST_F(InOrderExecuteUnitTest, ExecuteBranch) {
  input.getHeadSlots()[0] = uopPtr;

  // Anticipate testing instruction type; return true for branch
  ON_CALL(*uop, isBranch()).WillByDefault(Return(true));

  EXPECT_CALL(*uop, execute()).Times(1);

  bool taken = true;
  uint64_t pc = 1;
  uint64_t insnAddress = 2;

  EXPECT_CALL(*uop, getBranchAddress())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(pc));
  EXPECT_CALL(*uop, wasBranchTaken())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(taken));
  EXPECT_CALL(*uop, wasBranchMispredicted())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*uop, getInstructionAddress())
      .Times(AtLeast(1))
      .WillRepeatedly(Return(insnAddress));

  // Check that the branch predictor was updated with the results
  EXPECT_CALL(predictor, update(insnAddress, taken, pc)).Times(1);

  // Check that empty forwarding call is made
  EXPECT_CALL(forwardOperands, forwardOperands(IsEmpty(), IsEmpty())).Times(1);

  executeUnit.tick();

  EXPECT_EQ(executeUnit.shouldFlush(), false);
  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
}

}  // namespace inorder
}  // namespace simeng
