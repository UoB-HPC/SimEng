#include "../MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/RegisterFileSet.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/WritebackUnit.hh"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Field;
using ::testing::Return;
using ::testing::SetArgReferee;

namespace simeng {
namespace pipeline {

class PipelineWritebackUnitTest : public testing::Test {
 public:
  PipelineWritebackUnitTest()
      : input(1, {1, nullptr}),
        registerFileSet({{8, 2}}),
        uop(new MockInstruction),
        uopPtr(uop),
        writebackUnit(input, registerFileSet, [](auto insnId) {}) {}

 protected:
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>> input;
  RegisterFileSet registerFileSet;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
  WritebackUnit writebackUnit;
};

// Tests that a value is correctly written back, and the uop is cleared from the
// buffer
TEST_F(PipelineWritebackUnitTest, Tick) {
  input[0].getHeadSlots()[0] = uopPtr;
  uint64_t result = 1;
  std::vector<RegisterValue> results = {result};
  std::vector<Register> destinations = {{0, 1}};

  EXPECT_CALL(*uop, getResults())
      .WillOnce(Return(span<RegisterValue>(results.data(), results.size())));
  EXPECT_CALL(*uop, getDestinationRegisters())
      .WillOnce(
          Return(span<Register>(destinations.data(), destinations.size())));

  writebackUnit.tick();

  EXPECT_EQ(registerFileSet.get(destinations[0]).get<uint64_t>(), result);
  EXPECT_EQ(input[0].getHeadSlots()[0], nullptr);
}

}  // namespace pipeline
}  // namespace simeng
