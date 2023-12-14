#include "../MockInstruction.hh"
#include "../MockPortAllocator.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/ModelConfig.hh"
#include "simeng/pipeline/DispatchIssueUnit.hh"
#include "simeng/version.hh"

namespace simeng {
namespace pipeline {

using ::testing::Return;
using ::testing::ReturnRef;

class PipelineDispatchIssueUnitTest : public testing::Test {
 public:
  PipelineDispatchIssueUnitTest()
      : regFile(physRegStruct),
        input(1, nullptr),
        output(config["Execution-Units"].size(), {1, nullptr}),
        diUnit(input, output, regFile, portAlloc, physRegQuants, config),
        uop(new MockInstruction),
        uopPtr(uop),
        uop2(new MockInstruction),
        uop2Ptr(uop2) {}

 protected:
  YAML::Node config =
      simeng::ModelConfig(SIMENG_SOURCE_DIR "/configs/a64fx.yaml")
          .getConfigFile();

  // Using AArch64 as basis: {GP, FP/SVE, PRED, COND, SYS, SME}
  const std::vector<uint16_t> physRegQuants = {96, 128, 48, 128, 64, 64};
  const std::vector<RegisterFileStructure> physRegStruct = {
      {8, physRegQuants[0]}, {256, physRegQuants[1]}, {32, physRegQuants[2]},
      {1, physRegQuants[3]}, {8, physRegQuants[4]},   {256, physRegQuants[5]}};
  RegisterFileSet regFile;

  PipelineBuffer<std::shared_ptr<Instruction>> input;
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>> output;

  MockPortAllocator portAlloc;

  simeng::pipeline::DispatchIssueUnit diUnit;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
  MockInstruction* uop2;
  std::shared_ptr<Instruction> uop2Ptr;

  // As per a64fx.yaml
  const uint16_t EAGA = 5;    // Maps to RS index 2
  const uint8_t RS_EAGA = 2;  // RS associated with EAGA in A64FX
  const std::vector<uint64_t> refRsSizes = {20, 20, 10, 10, 19};

  const Register r0 = {0, 0};
  const Register r1 = {0, 1};
  const Register r2 = {0, 2};
};

// No instruction issued due to empty input buffer
TEST_F(PipelineDispatchIssueUnitTest, emptyTick) {
  // Ensure empty Reservation stations pre tick()
  std::vector<uint64_t> rsSizes;
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);

  diUnit.tick();
  // Post tick(), ensure RS sizes are still the same + no RS stalls
  rsSizes.clear();
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);
  EXPECT_EQ(diUnit.getRSStalls(), 0);

  diUnit.issue();
  // Post issue(), ensure Reservation stations are empty
  rsSizes.clear();
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);
  // Post issue(), ensure output buffers are empty
  for (size_t i = 0; i < output.size(); i++) {
    EXPECT_EQ(output[i].getTailSlots()[0], nullptr);
  }
  // Post issue(), ensure only front-end stall recorded
  EXPECT_EQ(diUnit.getFrontendStalls(), 1);
  EXPECT_EQ(diUnit.getBackendStalls(), 0);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
}

// Single instruction has no exception, 2 source operands (both ready), 1
// destination operand
TEST_F(PipelineDispatchIssueUnitTest, singleInstr) {
  // Set-up source & destination registers and ports for this instruction
  std::array<Register, 2> srcRegs = {r1, r2};
  std::array<Register, 1> destRegs = {r0};
  const std::vector<uint16_t> suppPorts = {EAGA};

  // All expected calls to instruction during tick()
  EXPECT_CALL(*uop, getSupportedPorts()).WillOnce(ReturnRef(suppPorts));
  uop->setExceptionEncountered(false);
  EXPECT_CALL(*uop, getSourceRegisters())
      .WillOnce(Return(span<Register>(srcRegs)));
  EXPECT_CALL(*uop, isOperandReady(0)).WillOnce(Return(false));
  EXPECT_CALL(*uop, supplyOperand(0, RegisterValue(0, 8)));
  EXPECT_CALL(*uop, isOperandReady(1)).WillOnce(Return(false));
  EXPECT_CALL(*uop, supplyOperand(1, RegisterValue(0, 8)));
  EXPECT_CALL(*uop, getDestinationRegisters())
      .WillOnce(Return(span<Register>(destRegs)));

  // Expected call to port allocator during tick()
  EXPECT_CALL(portAlloc, allocate(suppPorts)).WillOnce(Return(EAGA));

  // Ensure empty reservation stations pre tick()
  std::vector<uint64_t> rsSizes;
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);

  input.getHeadSlots()[0] = uopPtr;
  diUnit.tick();
  // Ensure post tick that EAGA's reservation station size has decreased by 1
  rsSizes.clear();
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes.size(), refRsSizes.size());
  EXPECT_EQ(rsSizes[RS_EAGA], refRsSizes[RS_EAGA] - 1);
  // Ensure no stalls recorded in tick()
  EXPECT_EQ(diUnit.getFrontendStalls(), 0);
  EXPECT_EQ(diUnit.getBackendStalls(), 0);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 0);
  // Ensure empty output buffers post tick()
  for (size_t i = 0; i < output.size(); i++) {
    EXPECT_EQ(output[i].getTailSlots()[0], nullptr);
  }

  // Detail expected call to port allocator during tick()
  EXPECT_CALL(portAlloc, issued(EAGA));

  diUnit.issue();
  // Ensure all reservation stations empty again post issue()
  rsSizes.clear();
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);
  // Ensure no stalls recorded during issue()
  EXPECT_EQ(diUnit.getFrontendStalls(), 0);
  EXPECT_EQ(diUnit.getBackendStalls(), 0);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 0);
  // Ensure all output buffers are empty, except the one associated with EAGA
  // port which contains the uop
  for (size_t i = 0; i < output.size(); i++) {
    if (i != EAGA)
      EXPECT_EQ(output[i].getTailSlots()[0], nullptr);
    else
      EXPECT_EQ(output[i].getTailSlots()[0].get(), uop);
  }
}

// Single instruction with exception
TEST_F(PipelineDispatchIssueUnitTest, singleInstr_excpetion) {
  // Setup supported port instruction can use
  const std::vector<uint16_t> suppPorts = {EAGA};

  // All expected calls to instruction during tick()
  EXPECT_CALL(*uop, getSupportedPorts()).WillOnce(ReturnRef(suppPorts));
  uop->setExceptionEncountered(true);

  input.getHeadSlots()[0] = uopPtr;
  diUnit.tick();
  // Check that instruction has encountered an exception and that it is ready to
  // commit
  EXPECT_TRUE(uop->canCommit());
  EXPECT_TRUE(uop->exceptionEncountered());
  // Ensure all reservation stations are empty post tick()
  std::vector<uint64_t> rsSizes;
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);
  // Ensure input buffer has been emptied
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);

  // Perform issue()
  diUnit.issue();
  // Ensure RS still empty post issue()
  rsSizes.clear();
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);
  // Ensure all output ports are empty
  for (int i = 0; i < output.size(); i++) {
    EXPECT_EQ(output[i].getTailSlots()[0], nullptr);
  }
  // Ensure frontend stall recorded
  EXPECT_EQ(diUnit.getFrontendStalls(), 1);
  EXPECT_EQ(diUnit.getBackendStalls(), 0);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 0);
}

// Single instruction that can't be issued in 1 cycle as RS is full
TEST_F(PipelineDispatchIssueUnitTest, singleInstr_rsFull) {
  // Setup supported port instructions can use
  const std::vector<uint16_t> suppPorts = {EAGA};

  // Artificially fill Reservation station with index 2
  std::vector<std::shared_ptr<MockInstruction>> insns(refRsSizes[RS_EAGA]);
  for (int i = 0; i < insns.size(); i++) {
    // Initialise instruction
    insns[i] = std::make_shared<MockInstruction>();
    // All expected calls to instruction during tick()
    EXPECT_CALL(*insns[i].get(), getSupportedPorts())
        .WillOnce(ReturnRef(suppPorts));
    EXPECT_CALL(*insns[i].get(), getSourceRegisters())
        .WillOnce(Return(span<Register>()));
    EXPECT_CALL(*insns[i].get(), getDestinationRegisters())
        .WillOnce(Return(span<Register>()));
    // Expected call to port allocator during tick()
    EXPECT_CALL(portAlloc, allocate(suppPorts)).WillOnce(Return(EAGA));

    input.getHeadSlots()[0] = insns[i];
    diUnit.tick();
  }
  // Ensure Reservation station index 2 is full post tick, and all others are
  // empty
  std::vector<uint64_t> rsSizes;
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes.size(), refRsSizes.size());
  for (int i = 0; i < refRsSizes.size(); i++) {
    if (i != RS_EAGA) {
      EXPECT_EQ(rsSizes[i], refRsSizes[i]);
    } else {
      EXPECT_EQ(rsSizes[i], 0);
      EXPECT_NE(rsSizes[i], refRsSizes[i]);
    }
  }
  // Ensure no stalls recorded in tick()
  EXPECT_EQ(diUnit.getFrontendStalls(), 0);
  EXPECT_EQ(diUnit.getBackendStalls(), 0);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 0);

  // Submit new instruction to same port
  // All expected calls to instruction during tick()
  EXPECT_CALL(*uop, getSupportedPorts()).WillOnce(ReturnRef(suppPorts));
  // All expected calls to portAllocator during tick()
  EXPECT_CALL(portAlloc, allocate(suppPorts)).WillOnce(Return(EAGA));
  EXPECT_CALL(portAlloc, deallocate(EAGA));
  input.getHeadSlots()[0] = uopPtr;
  diUnit.tick();
  // Ensure Reservation station sizes have stayed the same
  rsSizes.clear();
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes.size(), refRsSizes.size());
  for (int i = 0; i < refRsSizes.size(); i++) {
    if (i != RS_EAGA) {
      EXPECT_EQ(rsSizes[i], refRsSizes[i]);
    } else {
      EXPECT_EQ(rsSizes[i], 0);
      EXPECT_NE(rsSizes[i], refRsSizes[i]);
    }
  }
  // Check input pipelineBuffer stalled
  EXPECT_TRUE(input.isStalled());
  // Ensure one rsStall recorded in tick()
  EXPECT_EQ(diUnit.getFrontendStalls(), 0);
  EXPECT_EQ(diUnit.getBackendStalls(), 0);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 1);
}

// Single instruction not issued in 1 cycle as port is stalled
TEST_F(PipelineDispatchIssueUnitTest, singleInstr_portStall) {
  // Setup supported port instructions can use
  const std::vector<uint16_t> suppPorts = {EAGA};

  // Submit new instruction to a port
  // All expected calls to instruction during tick()
  EXPECT_CALL(*uop, getSupportedPorts()).WillOnce(ReturnRef(suppPorts));
  uop->setExceptionEncountered(false);
  EXPECT_CALL(*uop, getSourceRegisters()).WillOnce(Return(span<Register>()));
  EXPECT_CALL(*uop, getDestinationRegisters())
      .WillOnce(Return(span<Register>()));
  // Expected call to portAllocator during tick()
  EXPECT_CALL(portAlloc, allocate(suppPorts)).WillOnce(Return(EAGA));

  input.getHeadSlots()[0] = uopPtr;
  diUnit.tick();

  // Ensure correct RS sizes post tick()
  std::vector<uint64_t> rsSizes;
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes.size(), refRsSizes.size());
  for (int i = 0; i < refRsSizes.size(); i++) {
    if (i != RS_EAGA) {
      EXPECT_EQ(rsSizes[i], refRsSizes[i]);
    } else {
      EXPECT_EQ(rsSizes[i], refRsSizes[i] - 1);
    }
  }
  // Ensure no stalls recorded in tick()
  EXPECT_EQ(diUnit.getFrontendStalls(), 0);
  EXPECT_EQ(diUnit.getBackendStalls(), 0);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 0);

  // Stall issue port
  output[EAGA].stall(true);

  // Perform issue()
  diUnit.issue();
  // Ensure correct RS sizes post issue()
  rsSizes.clear();
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes.size(), refRsSizes.size());
  for (int i = 0; i < refRsSizes.size(); i++) {
    if (i != RS_EAGA) {
      EXPECT_EQ(rsSizes[i], refRsSizes[i]);
    } else {
      EXPECT_EQ(rsSizes[i], refRsSizes[i] - 1);
    }
  }
  // Ensure all output ports are empty
  for (int i = 0; i < output.size(); i++) {
    EXPECT_EQ(output[i].getTailSlots()[0], nullptr);
  }
  // Ensure portBusyStall and backend stall recorded in issue()
  EXPECT_EQ(diUnit.getFrontendStalls(), 0);
  EXPECT_EQ(diUnit.getBackendStalls(), 1);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 1);
  EXPECT_EQ(diUnit.getRSStalls(), 0);
}

// Try dispatch two instructions with RAW hazard after renaming, second should
// not be issued as it is dependant on first. Use forwardOpernad() to resolve
// dependancy.
TEST_F(PipelineDispatchIssueUnitTest, createDependancy_raw) {
  // Set-up source & destination registers and ports for the instructions
  std::array<Register, 1> srcRegs_1 = {};
  std::array<Register, 1> destRegs_1 = {r0};
  std::array<Register, 1> srcRegs_2 = {r0};
  std::array<Register, 1> destRegs_2 = {r1};
  const std::vector<uint16_t> suppPorts = {EAGA};

  // All expected calls to instruction 1 during tick()
  EXPECT_CALL(*uop, getSupportedPorts()).WillOnce(ReturnRef(suppPorts));
  uop->setExceptionEncountered(false);
  EXPECT_CALL(*uop, getSourceRegisters())
      .WillOnce(Return(span<Register>(srcRegs_1)));
  EXPECT_CALL(*uop, isOperandReady(0)).WillOnce(Return(false));
  EXPECT_CALL(*uop, supplyOperand(0, RegisterValue(0, 8)));
  EXPECT_CALL(*uop, getDestinationRegisters())
      .WillOnce(Return(span<Register>(destRegs_1)));
  // Expected call to port allocator during tick()
  EXPECT_CALL(portAlloc, allocate(suppPorts)).WillOnce(Return(EAGA));
  EXPECT_CALL(portAlloc, issued(EAGA));

  // Process instruction 1
  input.getHeadSlots()[0] = uopPtr;
  diUnit.tick();
  diUnit.issue();
  EXPECT_EQ(output[EAGA].getTailSlots()[0], uopPtr);
  output[EAGA].tick();

  // All expected calls to instruction 2 during tick()
  EXPECT_CALL(*uop2, getSupportedPorts()).WillOnce(ReturnRef(suppPorts));
  uop->setExceptionEncountered(false);
  EXPECT_CALL(*uop2, getSourceRegisters())
      .WillOnce(Return(span<Register>(srcRegs_2)));
  EXPECT_CALL(*uop2, isOperandReady(0)).WillOnce(Return(false));
  EXPECT_CALL(*uop2, getDestinationRegisters())
      .WillOnce(Return(span<Register>(destRegs_2)));
  // Expected call to port allocator during tick()
  EXPECT_CALL(portAlloc, allocate(suppPorts)).WillOnce(Return(EAGA));

  // Process instruction 2
  input.getHeadSlots()[0] = uop2Ptr;
  diUnit.tick();
  diUnit.issue();
  // Ensure correct RS sizes post tick() & issue()
  std::vector<uint64_t> rsSizes;
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes.size(), refRsSizes.size());
  for (int i = 0; i < refRsSizes.size(); i++) {
    if (i != RS_EAGA) {
      EXPECT_EQ(rsSizes[i], refRsSizes[i]);
    } else {
      EXPECT_EQ(rsSizes[i], refRsSizes[i] - 1);
    }
  }
  // Ensure all output ports are empty
  for (int i = 0; i < output.size(); i++) {
    EXPECT_EQ(output[i].getTailSlots()[0], nullptr);
  }
  // Ensure backend stall recorded in issue()
  EXPECT_EQ(diUnit.getFrontendStalls(), 0);
  EXPECT_EQ(diUnit.getBackendStalls(), 1);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 0);

  // Forward operand for register r0
  std::array<RegisterValue, 1> vals = {RegisterValue(6)};
  EXPECT_CALL(*uop2, supplyOperand(0, vals[0]));
  EXPECT_CALL(*uop2, canExecute()).WillOnce(Return(true));
  diUnit.forwardOperands(span<Register>(srcRegs_2), vals);

  // Try issue again for instruction 2
  EXPECT_CALL(portAlloc, issued(EAGA));
  diUnit.issue();
  // Ensure correct RS sizes post issue()
  rsSizes.clear();
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);
  // Ensure all output ports are empty except EAGA
  for (int i = 0; i < output.size(); i++) {
    if (i != EAGA)
      EXPECT_EQ(output[i].getTailSlots()[0], nullptr);
    else
      EXPECT_EQ(output[i].getTailSlots()[0], uop2Ptr);
  }
  // Ensure no further stalls recorded in issue()
  EXPECT_EQ(diUnit.getFrontendStalls(), 0);
  EXPECT_EQ(diUnit.getBackendStalls(), 1);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 0);
}

// Ensure correct instructions are flushed from reservation stations and the
// dependancy matrix
TEST_F(PipelineDispatchIssueUnitTest, purgeFlushed) {
  // Set-up source & destination registers and ports for the instructions;
  // creating a dependancy
  std::array<Register, 1> srcRegs_1 = {};
  std::array<Register, 1> destRegs_1 = {r0};
  std::array<Register, 1> srcRegs_2 = {r0};
  std::array<Register, 1> destRegs_2 = {r1};
  const std::vector<uint16_t> suppPorts = {EAGA};

  // All expected calls to instruction 1 during tick()
  EXPECT_CALL(*uop, getSupportedPorts()).WillOnce(ReturnRef(suppPorts));
  uop->setExceptionEncountered(false);
  EXPECT_CALL(*uop, getSourceRegisters())
      .WillOnce(Return(span<Register>(srcRegs_1)));
  EXPECT_CALL(*uop, isOperandReady(0)).WillOnce(Return(false));
  EXPECT_CALL(*uop, supplyOperand(0, RegisterValue(0, 8)));
  EXPECT_CALL(*uop, getDestinationRegisters())
      .WillOnce(Return(span<Register>(destRegs_1)));
  // Expected call to port allocator during tick()
  EXPECT_CALL(portAlloc, allocate(suppPorts)).WillOnce(Return(EAGA));

  // Process instruction 1
  input.getHeadSlots()[0] = uopPtr;
  diUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);

  // All expected calls to instruction 2 during tick()
  EXPECT_CALL(*uop2, getSupportedPorts()).WillOnce(ReturnRef(suppPorts));
  uop->setExceptionEncountered(false);
  EXPECT_CALL(*uop2, getSourceRegisters())
      .WillOnce(Return(span<Register>(srcRegs_2)));
  EXPECT_CALL(*uop2, isOperandReady(0)).WillOnce(Return(false));
  EXPECT_CALL(*uop2, getDestinationRegisters())
      .WillOnce(Return(span<Register>(destRegs_2)));
  // Expected call to port allocator during tick()
  EXPECT_CALL(portAlloc, allocate(suppPorts)).WillOnce(Return(EAGA));

  // Process instruction 2
  input.getHeadSlots()[0] = uop2Ptr;
  diUnit.tick();
  EXPECT_EQ(input.getHeadSlots()[0], nullptr);

  // Ensure correct RS sizes post tick()
  std::vector<uint64_t> rsSizes;
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes.size(), refRsSizes.size());
  for (int i = 0; i < refRsSizes.size(); i++) {
    if (i != RS_EAGA) {
      EXPECT_EQ(rsSizes[i], refRsSizes[i]);
    } else {
      EXPECT_EQ(rsSizes[i], refRsSizes[i] - 2);
    }
  }
  // Ensure all output ports are empty
  for (int i = 0; i < output.size(); i++) {
    EXPECT_EQ(output[i].getTailSlots()[0], nullptr);
  }
  // Ensure no stalls recorded
  EXPECT_EQ(diUnit.getFrontendStalls(), 0);
  EXPECT_EQ(diUnit.getBackendStalls(), 0);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 0);

  // Remove flushed uops
  EXPECT_CALL(portAlloc, deallocate(EAGA)).Times(2);
  uopPtr->setFlushed();
  uop2Ptr->setFlushed();
  diUnit.purgeFlushed();

  // Check reservation station sizes
  rsSizes.clear();
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);

  // Perform issue to see if `uop` is still present
  diUnit.issue();
  // Ensure all output ports are empty
  for (int i = 0; i < output.size(); i++) {
    EXPECT_EQ(output[i].getTailSlots()[0], nullptr);
  }
  // Ensure frontend stall recorded in issue()
  EXPECT_EQ(diUnit.getFrontendStalls(), 1);
  EXPECT_EQ(diUnit.getBackendStalls(), 0);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 0);

  // Call forwardOperand() and issue() to release `uop2` (if it were still
  // present)
  std::array<RegisterValue, 1> vals = {RegisterValue(6)};
  diUnit.forwardOperands(span<Register>(srcRegs_2), vals);
  // Check reservation station sizes
  rsSizes.clear();
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);

  diUnit.issue();
  // Ensure all output ports are empty
  for (int i = 0; i < output.size(); i++) {
    EXPECT_EQ(output[i].getTailSlots()[0], nullptr);
  }
  // Ensure frontend stall recorded in issue()
  EXPECT_EQ(diUnit.getFrontendStalls(), 2);
  EXPECT_EQ(diUnit.getBackendStalls(), 0);
  EXPECT_EQ(diUnit.getPortBusyStalls(), 0);
  EXPECT_EQ(diUnit.getRSStalls(), 0);
}

// Test based on a64fx config file reservation staion configuration
TEST_F(PipelineDispatchIssueUnitTest, getRSSizes) {
  std::vector<uint64_t> rsSizes;
  diUnit.getRSSizes(rsSizes);
  EXPECT_EQ(rsSizes, refRsSizes);
}

}  // namespace pipeline
}  // namespace simeng

// tick
// issue