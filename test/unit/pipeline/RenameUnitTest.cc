#include "../MockBranchPredictor.hh"
#include "../MockInstruction.hh"
#include "../MockMemoryInterface.hh"
#include "gtest/gtest.h"
#include "simeng/pipeline/RenameUnit.hh"

namespace simeng {

namespace pipeline {

using ::testing::_;
using ::testing::Return;

class RenameUnitTest : public testing::Test {
 public:
  RenameUnitTest()
      : input(1, nullptr),
        output(1, nullptr),
        rat(archRegFileStruct, physRegCounts),
        lsq(
            lsqQueueSize, lsqQueueSize, memory, completionSlots,
            [](auto registers, auto values) {}, [](auto insn) {}),
        rob(
            robSize, rat, lsq, [](auto insn) {}, [](auto branchAddr) {},
            predictor, 16, 4),
        renameUnit(input, output, rob, rat, lsq, physRegCounts.size()),
        uop(new MockInstruction),
        uop2(new MockInstruction),
        uop3(new MockInstruction),
        uopPtr(uop),
        uop2Ptr(uop2),
        uop3Ptr(uop3) {}

 protected:
  // 3rd register type has same arch & physical counts meaning renaming is not
  // permitted.
  const std::vector<RegisterFileStructure> archRegFileStruct = {
      {8, 10}, {24, 15}, {256, 31}};
  const std::vector<RegisterFileStructure> physRegFileStruct = {
      {8, 20}, {24, 30}, {256, 31}};
  const std::vector<uint16_t> physRegCounts = {20, 30, 31};

  const Register r0 = {0, 0};
  const Register r1 = {1, 2};
  const Register r2 = {2, 4};

  const uint64_t robSize = 8;
  const uint64_t lsqQueueSize = 10;

  PipelineBuffer<std::shared_ptr<Instruction>> input;
  PipelineBuffer<std::shared_ptr<Instruction>> output;

  MockMemoryInterface memory;
  MockBranchPredictor predictor;
  span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots;

  RegisterAliasTable rat;
  LoadStoreQueue lsq;
  ReorderBuffer rob;

  RenameUnit renameUnit;

  MockInstruction* uop;
  MockInstruction* uop2;
  MockInstruction* uop3;

  std::shared_ptr<Instruction> uopPtr;
  std::shared_ptr<Instruction> uop2Ptr;
  std::shared_ptr<Instruction> uop3Ptr;
};

// Test the correct functionality when input buffer and unit is empty
TEST_F(RenameUnitTest, emptyTick) {
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);

  renameUnit.tick();

  // Check output buffers and statistics are as expected
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  EXPECT_EQ(renameUnit.getAllocationStalls(), 0);
  EXPECT_EQ(renameUnit.getROBStalls(), 0);
  EXPECT_EQ(renameUnit.getLoadQueueStalls(), 0);
  EXPECT_EQ(renameUnit.getStoreQueueStalls(), 0);
}

// Test the normal functionality of an instruction passing through the unit
TEST_F(RenameUnitTest, tick) {
  input.getHeadSlots()[0] = uopPtr;

  std::array<Register, 1> destRegs = {r0};
  std::array<Register, 2> srcRegs = {r0, r1};
  ON_CALL(*uop, getDestinationRegisters())
      .WillByDefault(Return(span<Register>(destRegs)));
  ON_CALL(*uop, getSourceRegisters())
      .WillByDefault(Return(span<Register>(srcRegs)));
  ON_CALL(*uop, isOperandReady(_)).WillByDefault(Return(false));
  ON_CALL(*uop, isLoad()).WillByDefault(Return(false));
  ON_CALL(*uop, isStoreAddress()).WillByDefault(Return(false));

  // Setup expected calls to MockInstruction
  EXPECT_CALL(*uop, isLoad()).Times(1);
  EXPECT_CALL(*uop, isStoreAddress()).Times(1);
  EXPECT_CALL(*uop, getDestinationRegisters()).Times(1);
  EXPECT_CALL(*uop, getSourceRegisters()).Times(1);
  EXPECT_CALL(*uop, isOperandReady(_)).Times(2);
  EXPECT_CALL(*uop, renameSource(_, _)).Times(2);
  EXPECT_CALL(*uop, renameDestination(0, _)).Times(1);
  renameUnit.tick();

  // Check output buffers and statistics are as expected
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
  EXPECT_EQ(renameUnit.getAllocationStalls(), 0);
  EXPECT_EQ(renameUnit.getROBStalls(), 0);
  EXPECT_EQ(renameUnit.getLoadQueueStalls(), 0);
  EXPECT_EQ(renameUnit.getStoreQueueStalls(), 0);

  // Check ROB, LSQ, and RAT mappings have been changed accordingly
  EXPECT_EQ(rob.size(), 1);
  EXPECT_EQ(rob.getFreeSpace(), robSize - 1);
  EXPECT_EQ(lsq.getTotalSpace(), lsqQueueSize * 2);
  const Register mappedReg = {0, archRegFileStruct[0].quantity};
  EXPECT_EQ(rat.getMapping(r0), mappedReg);
  EXPECT_EQ(rat.getMapping(r1), r1);
}

// Ensure input buffer is stalled when output buffer is stalled
TEST_F(RenameUnitTest, outputStall) {
  output.stall(true);
  renameUnit.tick();
  EXPECT_TRUE(input.isStalled());
}

// Test that an instruction exception is properly dealt with
TEST_F(RenameUnitTest, uopException) {
  input.getHeadSlots()[0] = uopPtr;
  uop->setExceptionEncountered(true);

  renameUnit.tick();

  EXPECT_TRUE(uopPtr->canCommit());

  EXPECT_EQ(rob.size(), 1);
  EXPECT_EQ(rob.getFreeSpace(), robSize - 1);
  EXPECT_EQ(lsq.getTotalSpace(), lsqQueueSize * 2);
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);

  EXPECT_EQ(renameUnit.getAllocationStalls(), 0);
  EXPECT_EQ(renameUnit.getROBStalls(), 0);
  EXPECT_EQ(renameUnit.getLoadQueueStalls(), 0);
  EXPECT_EQ(renameUnit.getStoreQueueStalls(), 0);
}

// Test for when no physical registers are available
TEST_F(RenameUnitTest, noFreeRegs) {
  // Take up all type-0 physical registers
  // All arch regs originally mapped to phys reg, meaning remaing
  // regs = physCount - archCount
  for (int i = 0; i < physRegCounts[0] - archRegFileStruct[0].quantity; i++) {
    rat.allocate(r0);
  }
  EXPECT_EQ(rat.freeRegistersAvailable(0), 0);

  input.getHeadSlots()[0] = uopPtr;

  std::array<Register, 1> destRegs = {r0};
  ON_CALL(*uop, getDestinationRegisters())
      .WillByDefault(Return(span<Register>(destRegs)));
  ON_CALL(*uop, isOperandReady(_)).WillByDefault(Return(false));
  ON_CALL(*uop, isLoad()).WillByDefault(Return(false));
  ON_CALL(*uop, isStoreAddress()).WillByDefault(Return(false));

  // Setup expected calls to MockInstruction
  EXPECT_CALL(*uop, isLoad()).Times(1);
  EXPECT_CALL(*uop, isStoreAddress()).Times(1);
  EXPECT_CALL(*uop, getDestinationRegisters()).Times(1);
  renameUnit.tick();

  EXPECT_TRUE(input.isStalled());

  EXPECT_EQ(rob.size(), 0);
  EXPECT_EQ(rob.getFreeSpace(), robSize);
  EXPECT_EQ(lsq.getTotalSpace(), lsqQueueSize * 2);
  EXPECT_EQ(input.getHeadSlots()[0], uopPtr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);

  EXPECT_EQ(renameUnit.getAllocationStalls(), 1);
  EXPECT_EQ(renameUnit.getROBStalls(), 0);
  EXPECT_EQ(renameUnit.getLoadQueueStalls(), 0);
  EXPECT_EQ(renameUnit.getStoreQueueStalls(), 0);
}

// Tests that when ROB is full, no renaming occurs
TEST_F(RenameUnitTest, fullROB) {
  // Pre-fill ROB
  for (uint64_t i = 0; i < robSize; i++) {
    rob.reserve(uopPtr);
  }
  EXPECT_EQ(rob.getFreeSpace(), 0);

  input.getHeadSlots()[0] = uopPtr;
  renameUnit.tick();

  EXPECT_TRUE(input.isStalled());

  EXPECT_EQ(rob.size(), robSize);
  EXPECT_EQ(rob.getFreeSpace(), 0);
  EXPECT_EQ(lsq.getTotalSpace(), lsqQueueSize * 2);
  EXPECT_EQ(input.getHeadSlots()[0], uopPtr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);

  EXPECT_EQ(renameUnit.getAllocationStalls(), 0);
  EXPECT_EQ(renameUnit.getROBStalls(), 1);
  EXPECT_EQ(renameUnit.getLoadQueueStalls(), 0);
  EXPECT_EQ(renameUnit.getStoreQueueStalls(), 0);
}

// Test a LOAD instruction is handled correctly
TEST_F(RenameUnitTest, loadUop) {
  input.getHeadSlots()[0] = uopPtr;

  std::array<Register, 1> destRegs = {r0};
  std::array<Register, 2> srcRegs = {r0, r1};
  ON_CALL(*uop, getDestinationRegisters())
      .WillByDefault(Return(span<Register>(destRegs)));
  ON_CALL(*uop, getSourceRegisters())
      .WillByDefault(Return(span<Register>(srcRegs)));
  ON_CALL(*uop, isOperandReady(_)).WillByDefault(Return(false));
  ON_CALL(*uop, isLoad()).WillByDefault(Return(true));
  ON_CALL(*uop, isStoreAddress()).WillByDefault(Return(false));

  // Setup expected calls to MockInstruction
  EXPECT_CALL(*uop, isLoad()).Times(1);
  EXPECT_CALL(*uop, isStoreAddress()).Times(1);
  EXPECT_CALL(*uop, getDestinationRegisters()).Times(1);
  EXPECT_CALL(*uop, getSourceRegisters()).Times(1);
  EXPECT_CALL(*uop, isOperandReady(_)).Times(2);
  EXPECT_CALL(*uop, renameSource(_, _)).Times(2);
  EXPECT_CALL(*uop, renameDestination(0, _)).Times(1);
  renameUnit.tick();

  // Check output buffers and statistics are as expected
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
  EXPECT_EQ(renameUnit.getAllocationStalls(), 0);
  EXPECT_EQ(renameUnit.getROBStalls(), 0);
  EXPECT_EQ(renameUnit.getLoadQueueStalls(), 0);
  EXPECT_EQ(renameUnit.getStoreQueueStalls(), 0);

  // Check ROB, LSQ, and RAT mappings have been changed accordingly
  EXPECT_EQ(rob.size(), 1);
  EXPECT_EQ(rob.getFreeSpace(), robSize - 1);
  EXPECT_EQ(lsq.getLoadQueueSpace(), lsqQueueSize - 1);
  EXPECT_EQ(lsq.getStoreQueueSpace(), lsqQueueSize);
  EXPECT_EQ(lsq.getTotalSpace(), (lsqQueueSize * 2) - 1);
  const Register mappedReg = {0, archRegFileStruct[0].quantity};
  EXPECT_EQ(rat.getMapping(r0), mappedReg);
  EXPECT_EQ(rat.getMapping(r1), r1);
}

// Test a LOAD instruction is handled correctly when Load queue is full
TEST_F(RenameUnitTest, loadUopQueueFull) {
  // pre-fill Load Queue
  for (uint64_t i = 0; i < lsqQueueSize; i++) {
    lsq.addLoad(uopPtr);
  }
  EXPECT_EQ(lsq.getLoadQueueSpace(), 0);

  input.getHeadSlots()[0] = uopPtr;

  std::array<Register, 1> destRegs = {r0};
  std::array<Register, 2> srcRegs = {r0, r1};
  ON_CALL(*uop, getDestinationRegisters())
      .WillByDefault(Return(span<Register>(destRegs)));
  ON_CALL(*uop, getSourceRegisters())
      .WillByDefault(Return(span<Register>(srcRegs)));
  ON_CALL(*uop, isOperandReady(_)).WillByDefault(Return(false));
  ON_CALL(*uop, isLoad()).WillByDefault(Return(true));
  ON_CALL(*uop, isStoreAddress()).WillByDefault(Return(false));

  // Setup expected calls to MockInstruction
  EXPECT_CALL(*uop, isLoad()).Times(1);
  EXPECT_CALL(*uop, isStoreAddress()).Times(1);
  renameUnit.tick();

  EXPECT_TRUE(input.isStalled());

  // Check output buffers and statistics are as expected
  EXPECT_EQ(input.getHeadSlots()[0], uopPtr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  EXPECT_EQ(renameUnit.getAllocationStalls(), 0);
  EXPECT_EQ(renameUnit.getROBStalls(), 0);
  EXPECT_EQ(renameUnit.getLoadQueueStalls(), 1);
  EXPECT_EQ(renameUnit.getStoreQueueStalls(), 0);

  // Check ROB, LSQ, and RAT mappings have been changed accordingly
  EXPECT_EQ(rob.size(), 0);
  EXPECT_EQ(rob.getFreeSpace(), robSize);
  EXPECT_EQ(lsq.getLoadQueueSpace(), 0);
  EXPECT_EQ(lsq.getStoreQueueSpace(), lsqQueueSize);
  EXPECT_EQ(lsq.getTotalSpace(), lsqQueueSize);
}

// Test a STORE instruction is handled correctly
TEST_F(RenameUnitTest, storeUop) {
  input.getHeadSlots()[0] = uopPtr;

  std::array<Register, 1> destRegs = {r0};
  std::array<Register, 2> srcRegs = {r0, r1};
  ON_CALL(*uop, getDestinationRegisters())
      .WillByDefault(Return(span<Register>(destRegs)));
  ON_CALL(*uop, getSourceRegisters())
      .WillByDefault(Return(span<Register>(srcRegs)));
  ON_CALL(*uop, isOperandReady(_)).WillByDefault(Return(false));
  ON_CALL(*uop, isLoad()).WillByDefault(Return(false));
  ON_CALL(*uop, isStoreAddress()).WillByDefault(Return(true));

  // Setup expected calls to MockInstruction
  EXPECT_CALL(*uop, isLoad()).Times(1);
  EXPECT_CALL(*uop, isStoreAddress()).Times(1);
  EXPECT_CALL(*uop, getDestinationRegisters()).Times(1);
  EXPECT_CALL(*uop, getSourceRegisters()).Times(1);
  EXPECT_CALL(*uop, isOperandReady(_)).Times(2);
  EXPECT_CALL(*uop, renameSource(_, _)).Times(2);
  EXPECT_CALL(*uop, renameDestination(0, _)).Times(1);
  renameUnit.tick();

  // Check output buffers and statistics are as expected
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
  EXPECT_EQ(renameUnit.getAllocationStalls(), 0);
  EXPECT_EQ(renameUnit.getROBStalls(), 0);
  EXPECT_EQ(renameUnit.getLoadQueueStalls(), 0);
  EXPECT_EQ(renameUnit.getStoreQueueStalls(), 0);

  // Check ROB, LSQ, and RAT mappings have been changed accordingly
  EXPECT_EQ(rob.size(), 1);
  EXPECT_EQ(rob.getFreeSpace(), robSize - 1);
  EXPECT_EQ(lsq.getLoadQueueSpace(), lsqQueueSize);
  EXPECT_EQ(lsq.getStoreQueueSpace(), lsqQueueSize - 1);
  EXPECT_EQ(lsq.getTotalSpace(), (lsqQueueSize * 2) - 1);
  const Register mappedReg = {0, archRegFileStruct[0].quantity};
  EXPECT_EQ(rat.getMapping(r0), mappedReg);
  EXPECT_EQ(rat.getMapping(r1), r1);
}

// Test a STORE instruction is handled correctly when Store queue is full
TEST_F(RenameUnitTest, storeUopQueueFull) {
  // pre-fill Load Queue
  for (uint64_t i = 0; i < lsqQueueSize; i++) {
    lsq.addStore(uopPtr);
  }
  EXPECT_EQ(lsq.getStoreQueueSpace(), 0);

  input.getHeadSlots()[0] = uopPtr;

  std::array<Register, 1> destRegs = {r0};
  std::array<Register, 2> srcRegs = {r0, r1};
  ON_CALL(*uop, getDestinationRegisters())
      .WillByDefault(Return(span<Register>(destRegs)));
  ON_CALL(*uop, getSourceRegisters())
      .WillByDefault(Return(span<Register>(srcRegs)));
  ON_CALL(*uop, isOperandReady(_)).WillByDefault(Return(false));
  ON_CALL(*uop, isLoad()).WillByDefault(Return(false));
  ON_CALL(*uop, isStoreAddress()).WillByDefault(Return(true));

  // Setup expected calls to MockInstruction
  EXPECT_CALL(*uop, isLoad()).Times(1);
  EXPECT_CALL(*uop, isStoreAddress()).Times(1);
  renameUnit.tick();

  EXPECT_TRUE(input.isStalled());

  // Check output buffers and statistics are as expected
  EXPECT_EQ(input.getHeadSlots()[0], uopPtr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);
  EXPECT_EQ(renameUnit.getAllocationStalls(), 0);
  EXPECT_EQ(renameUnit.getROBStalls(), 0);
  EXPECT_EQ(renameUnit.getLoadQueueStalls(), 0);
  EXPECT_EQ(renameUnit.getStoreQueueStalls(), 1);

  // Check ROB, LSQ, and RAT mappings have been changed accordingly
  EXPECT_EQ(rob.size(), 0);
  EXPECT_EQ(rob.getFreeSpace(), robSize);
  EXPECT_EQ(lsq.getLoadQueueSpace(), lsqQueueSize);
  EXPECT_EQ(lsq.getStoreQueueSpace(), 0);
  EXPECT_EQ(lsq.getTotalSpace(), lsqQueueSize);
}

// Test to ensure Serialized destinations work correctly
TEST_F(RenameUnitTest, serializedDest) {
  // A serialized uop can only proceed when the ROB is empty. Pre-add an
  // instruction to ensure uop stalls correctly in renameUnit Pre-fill ROB
  rob.reserve(uop2Ptr);
  EXPECT_EQ(rob.size(), 1);

  // A serialized uop is caused when the destination register cannot be renamed
  // - i.e. the number of archRegs is the same as physRegs
  input.getHeadSlots()[0] = uopPtr;
  std::array<Register, 1> destRegs = {r2};
  std::array<Register, 2> srcRegs = {r0, r1};
  ON_CALL(*uop, getDestinationRegisters())
      .WillByDefault(Return(span<Register>(destRegs)));
  ON_CALL(*uop, getSourceRegisters())
      .WillByDefault(Return(span<Register>(srcRegs)));
  ON_CALL(*uop, isOperandReady(_)).WillByDefault(Return(false));
  ON_CALL(*uop, isLoad()).WillByDefault(Return(false));
  ON_CALL(*uop, isStoreAddress()).WillByDefault(Return(false));

  // On first tick, input should stall and uop should not proceed through
  // renameUnit
  EXPECT_CALL(*uop, isLoad()).Times(1);
  EXPECT_CALL(*uop, isStoreAddress()).Times(1);
  EXPECT_CALL(*uop, getDestinationRegisters()).Times(1);
  renameUnit.tick();

  EXPECT_TRUE(input.isStalled());
  EXPECT_EQ(input.getHeadSlots()[0], uopPtr);
  EXPECT_EQ(output.getTailSlots()[0], nullptr);

  // Empty item in ROB
  EXPECT_EQ(rob.size(), 1);
  uop2Ptr->setCommitReady();
  EXPECT_CALL(*uop2, getDestinationRegisters()).Times(1);
  EXPECT_CALL(*uop2, isLoad()).WillOnce(Return(false));
  EXPECT_CALL(*uop2, isStoreAddress()).WillOnce(Return(false));
  EXPECT_CALL(*uop2, isBranch()).Times(2).WillRepeatedly(Return(false));
  rob.commit(1);
  EXPECT_EQ(rob.size(), 0);

  // Try tick again
  EXPECT_CALL(*uop, isLoad()).Times(1);
  EXPECT_CALL(*uop, isStoreAddress()).Times(1);
  EXPECT_CALL(*uop, getDestinationRegisters()).Times(1);
  EXPECT_CALL(*uop, getSourceRegisters()).Times(1);
  EXPECT_CALL(*uop, isOperandReady(_)).Times(2);
  EXPECT_CALL(*uop, renameSource(_, _)).Times(2);
  renameUnit.tick();

  // Check output buffers and statistics are as expected
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);
  EXPECT_EQ(output.getTailSlots()[0].get(), uop);
  EXPECT_EQ(renameUnit.getAllocationStalls(), 0);
  EXPECT_EQ(renameUnit.getROBStalls(), 0);
  EXPECT_EQ(renameUnit.getLoadQueueStalls(), 0);
  EXPECT_EQ(renameUnit.getStoreQueueStalls(), 0);

  // Check ROB, LSQ, and RAT mappings have been changed accordingly
  EXPECT_EQ(rob.size(), 1);
  EXPECT_EQ(rob.getFreeSpace(), robSize - 1);
  EXPECT_EQ(lsq.getTotalSpace(), lsqQueueSize * 2);
  EXPECT_EQ(rat.getMapping(r0), r0);
  EXPECT_EQ(rat.getMapping(r1), r1);
  EXPECT_EQ(rat.getMapping(r2), r2);
}

}  // namespace pipeline
}  // namespace simeng