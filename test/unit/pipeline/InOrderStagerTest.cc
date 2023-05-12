#include <memory>

#include "../MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"
#include "simeng/pipeline/BlockingIssueUnit.hh"

using ::testing::_;
using ::testing::Invoke;
using ::testing::Property;
using ::testing::Return;

namespace simeng {
namespace pipeline {

const uint8_t MAX_LOADS = 32;
const uint8_t MAX_STORES = 32;

class PipelineInOrderStagerTest : public testing::Test {
 public:
  PipelineInOrderStagerTest()
      : inOrderStagerUnit(),
        uop(new MockInstruction),
        uopPtr(uop),
        uop2(new MockInstruction),
        uopPtr2(uop2) {
    uop->setInstructionId(1);
    uop->setSequenceId(1);
    uop2->setInstructionId(2);
    uop2->setSequenceId(2);
    ON_CALL(*uop, getSupportedPorts())
        .WillByDefault(Invoke([this]() -> const std::vector<uint16_t>& {
          return supportedPorts;
        }));
    ON_CALL(*uop2, getSupportedPorts())
        .WillByDefault(Invoke([this]() -> const std::vector<uint16_t>& {
          return supportedPorts;
        }));
  }

 protected:
  InOrderStager inOrderStagerUnit;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
  MockInstruction* uop2;
  std::shared_ptr<Instruction> uopPtr2;

  const std::vector<uint16_t> supportedPorts;
};

// Tests that the InOrder Stager unit records/tracks issued instructions
// correctly
TEST_F(PipelineInOrderStagerTest, RecordIssue) {
  inOrderStagerUnit.recordIssue(uopPtr);
  inOrderStagerUnit.recordIssue(uopPtr2);

  EXPECT_EQ(inOrderStagerUnit.getNextSeqID(), 1);
  EXPECT_EQ(inOrderStagerUnit.canWriteback(uop->getSequenceId()), true);
  EXPECT_EQ(inOrderStagerUnit.canWriteback(uop2->getSequenceId()), false);
  inOrderStagerUnit.recordRetired(uop->getSequenceId());
  EXPECT_EQ(inOrderStagerUnit.getNextSeqID(), 2);
  EXPECT_EQ(inOrderStagerUnit.canWriteback(uop2->getSequenceId()), true);
}

// Tests that the InOrder Stager unit flush logic is correct
TEST_F(PipelineInOrderStagerTest, Flush) {
  inOrderStagerUnit.recordIssue(uopPtr);
  inOrderStagerUnit.recordIssue(uopPtr2);
  inOrderStagerUnit.flush();
  EXPECT_EQ(inOrderStagerUnit.getNextSeqID(), -1);

  inOrderStagerUnit.recordIssue(uopPtr);
  inOrderStagerUnit.recordIssue(uopPtr2);
  inOrderStagerUnit.flush(uop->getInstructionId());
  EXPECT_EQ(inOrderStagerUnit.getNextSeqID(), uop->getSequenceId());
}

}  // namespace pipeline
}  // namespace simeng
