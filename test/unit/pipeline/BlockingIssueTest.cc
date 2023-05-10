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

class PipelineBlockingIssueTest : public testing::Test {
 public:
  PipelineBlockingIssueTest()
      : input(2, nullptr),
        output({{1, nullptr}, {1, nullptr}}),
        registerFileSet({{8, 32}}),
        physicalRegisterStructure({32}),
        blockingIssueUnit(
            input, output, *portAllocator, [](auto insn) {}, lsq,
            [](auto insn) {}, registerFileSet, physicalRegisterStructure),
        uop(new MockInstruction),
        uopPtr(uop),
        uop2(new MockInstruction),
        uopPtr2(uop2),
        supportedPorts({0, 1}) {
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
  PipelineBuffer<std::shared_ptr<Instruction>> input;
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>> output;
  std::vector<std::vector<uint16_t>> portArrangement = {{0}, {1}};
  std::unique_ptr<PortAllocator> portAllocator =
      std::make_unique<BalancedPortAllocator>(portArrangement);

  VAddrTranslator fn = [](uint64_t vaddr, uint64_t pid) -> uint64_t {
    return vaddr;
  };
  std::shared_ptr<memory::MMU> mmu = std::make_shared<memory::MMU>(fn);
  std::vector<pipeline::PipelineBuffer<std::shared_ptr<Instruction>>>
      completionSlots = {{1, nullptr}};
  LoadStoreQueue lsq =
      LoadStoreQueue(MAX_LOADS, MAX_STORES, mmu,
                     {completionSlots.data(), completionSlots.size()},
                     [this](auto regs, auto values) {
                       blockingIssueUnit.forwardOperands(regs, values);
                     });

  const RegisterFileSet registerFileSet;
  const std::vector<uint16_t> physicalRegisterStructure;

  BlockingIssueUnit blockingIssueUnit;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
  MockInstruction* uop2;
  std::shared_ptr<Instruction> uopPtr2;

  const std::vector<uint16_t> supportedPorts;
};

// Tests that the blockingIssue unit output remains empty when an empty uop
// is present
TEST_F(PipelineBlockingIssueTest, TickEmpty) {
  blockingIssueUnit.tick();

  EXPECT_EQ(output[0].getTailSlots()[0], nullptr);
}

// Tests that the blockingIssue unit output is correctly populated when supplied
// with two uops
TEST_F(PipelineBlockingIssueTest, Tick) {
  input.getHeadSlots()[0] = {uopPtr};
  input.getHeadSlots()[1] = {uopPtr2};

  std::vector<Register> uopSrcOps = {{0, 0}};
  const span<Register> uopSrcSpan(uopSrcOps.data(), uopSrcOps.size());
  std::vector<Register> uop2SrcOps = {{0, 1}};
  const span<Register> uop2SrcSpan(uop2SrcOps.data(), uop2SrcOps.size());

  EXPECT_CALL(*uop, getOperandRegisters()).WillRepeatedly(Return(uopSrcSpan));
  EXPECT_CALL(*uop2, getOperandRegisters()).WillRepeatedly(Return(uop2SrcSpan));

  EXPECT_CALL(*uop, isOperandReady(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*uop2, isOperandReady(_)).WillRepeatedly(Return(true));

  blockingIssueUnit.tick();
  output[0].tick();
  blockingIssueUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0].get(), nullptr);
  EXPECT_EQ(input.getHeadSlots()[1].get(), nullptr);
  EXPECT_EQ(output[0].getHeadSlots()[0].get(), uop);
  EXPECT_EQ(output[0].getTailSlots()[0].get(), uop2);
}

// Tests that the blockingIssue unit output is correctly populated when supplied
// with two uops with a RAW dependency
TEST_F(PipelineBlockingIssueTest, TickWithRAW) {
  input.getHeadSlots()[0] = {uopPtr};
  input.getHeadSlots()[1] = {uopPtr2};

  // Setup operands to create a RAW dependency
  std::vector<Register> uopDestOps = {{0, 0}};
  const span<Register> uopDestSpan(uopDestOps.data(), uopDestOps.size());
  std::vector<Register> uop2SrcOps = {{0, 0}, {0, 1}, {0, 2}};
  const span<Register> uop2SrcSpan(uop2SrcOps.data(), uop2SrcOps.size());
  std::vector<Register> otherSrcOps = {{0, 4}, {0, 5}, {0, 6}};
  const span<Register> otherSrcSpan(otherSrcOps.data(), otherSrcOps.size());

  EXPECT_CALL(*uop, getDestinationRegisters())
      .WillRepeatedly(Return(uopDestSpan));
  EXPECT_CALL(*uop2, getOperandRegisters()).WillRepeatedly(Return(uop2SrcSpan));

  EXPECT_CALL(*uop, isOperandReady(_)).WillRepeatedly(Return(true));
  EXPECT_CALL(*uop2, isOperandReady(0)).WillRepeatedly(Return(false));
  EXPECT_CALL(*uop2, isOperandReady(1)).WillRepeatedly(Return(true));
  EXPECT_CALL(*uop2, isOperandReady(2)).WillRepeatedly(Return(true));

  blockingIssueUnit.tick();
  output[0].tick();
  blockingIssueUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0].get(), nullptr);
  EXPECT_EQ(input.getHeadSlots()[1].get(), nullptr);
  EXPECT_EQ(output[0].getHeadSlots()[0].get(), uop);
  EXPECT_EQ(output[0].getTailSlots()[0].get(), nullptr);
  EXPECT_CALL(*uop2, canExecute()).Times(1).WillOnce(Return(true));

  // Resolve RAW
  std::vector<RegisterValue> vals1 = {{1, 8}};
  const span<RegisterValue> val1Span(vals1.data(), vals1.size());
  std::vector<RegisterValue> vals3 = {{1, 8}, {2, 8}, {3, 8}};
  const span<RegisterValue> val3Span(vals3.data(), vals3.size());

  blockingIssueUnit.forwardOperands(otherSrcSpan, val3Span);
  blockingIssueUnit.tick();
  EXPECT_EQ(output[0].getTailSlots()[0].get(), nullptr);

  blockingIssueUnit.forwardOperands(uopDestSpan, val1Span);
  blockingIssueUnit.tick();
  EXPECT_EQ(output[0].getTailSlots()[0].get(), uop2);
}

// Tests that the blockingIssue unit output is correctly populated when supplied
// with two uops with a WAW dependency
TEST_F(PipelineBlockingIssueTest, TickWithWAW) {
  input.getHeadSlots()[0] = {uopPtr};
  input.getHeadSlots()[1] = {uopPtr2};

  // Setup operands to create a WAW dependency
  std::vector<Register> uopDestOps = {{0, 0}, {0, 1}, {0, 2}};
  const span<Register> uopDestSpan(uopDestOps.data(), uopDestOps.size());
  std::vector<Register> uop2DestOps = {{0, 1}};
  const span<Register> uop2DestSpan(uop2DestOps.data(), uop2DestOps.size());

  EXPECT_CALL(*uop, getDestinationRegisters())
      .WillRepeatedly(Return(uopDestSpan));
  EXPECT_CALL(*uop2, getDestinationRegisters())
      .WillRepeatedly(Return(uop2DestSpan));

  blockingIssueUnit.tick();
  output[0].tick();
  blockingIssueUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0].get(), nullptr);
  EXPECT_EQ(input.getHeadSlots()[1].get(), nullptr);
  EXPECT_EQ(output[0].getHeadSlots()[0].get(), uop);
  EXPECT_EQ(output[0].getTailSlots()[0].get(), nullptr);
  blockingIssueUnit.tick();
  EXPECT_EQ(output[0].getTailSlots()[0].get(), nullptr);

  // Resolve WAW
  blockingIssueUnit.setRegisterReady({0, 1});
  blockingIssueUnit.tick();
  EXPECT_EQ(output[0].getTailSlots()[0].get(), uop2);
}

// Tests that the blockingIssue unit flushing is correct
TEST_F(PipelineBlockingIssueTest, FlushAfterId) {
  uop->setInstructionId(1);
  uop2->setInstructionId(2);

  input.getHeadSlots()[0] = {uopPtr};
  input.getHeadSlots()[1] = {uopPtr2};

  // Register a RAW and WAW dependency to prevent uop2 exiting the unit
  std::vector<Register> uopDestOps = {{0, 0}, {0, 1}, {0, 2}};
  const span<Register> uopDestSpan(uopDestOps.data(), uopDestOps.size());
  std::vector<Register> uop2DestOps = {{0, 1}};
  const span<Register> uop2DestSpan(uop2DestOps.data(), uop2DestOps.size());
  std::vector<Register> uop2SrcOps = {{0, 0}};
  const span<Register> uop2SrcSpan(uop2SrcOps.data(), uop2SrcOps.size());

  EXPECT_CALL(*uop, getDestinationRegisters())
      .WillRepeatedly(Return(uopDestSpan));
  EXPECT_CALL(*uop2, getDestinationRegisters())
      .WillRepeatedly(Return(uop2DestSpan));
  EXPECT_CALL(*uop2, getOperandRegisters()).WillRepeatedly(Return(uop2SrcSpan));

  blockingIssueUnit.tick();
  output[0].tick();
  blockingIssueUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0].get(), nullptr);
  EXPECT_EQ(input.getHeadSlots()[1].get(), nullptr);
  EXPECT_EQ(output[0].getHeadSlots()[0].get(), uop);
  EXPECT_EQ(output[0].getTailSlots()[0].get(), nullptr);

  blockingIssueUnit.flush(0);
  // After the flush, all dependencies should be wiped and thus uop2 can exit
  // the unit
  blockingIssueUnit.tick();
  EXPECT_EQ(output[0].getTailSlots()[0].get(), nullptr);
  input.getHeadSlots()[0] = {uopPtr2};
  blockingIssueUnit.tick();
  EXPECT_EQ(output[0].getTailSlots()[0].get(), uop2);
}

}  // namespace pipeline
}  // namespace simeng
