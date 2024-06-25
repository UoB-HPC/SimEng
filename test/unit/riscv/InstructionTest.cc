#include "../ConfigInit.hh"
#include "arch/riscv/InstructionMetadata.hh"
#include "gmock/gmock.h"
#include "simeng/arch/riscv/Instruction.hh"
#include "simeng/version.hh"

namespace simeng {
namespace arch {
namespace riscv {

// RiscV Instruction Tests
class RiscVInstructionTest : public testing::Test {
 public:
  RiscVInstructionTest()
      : os(config::SimInfo::getConfig()["CPU-Info"]["Special-File-Dir-Path"]
               .as<std::string>()),
        arch(os) {
    // Create InstructionMetadata objects
    cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &capstoneHandle);
    cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);

    // Create instructions which cover the 3 main types: Arithmetic, Memory,
    // Branch. This allows for full testing of the Instruction class.

    // div
    cs_insn rawInsn_div;
    cs_detail rawDetail_div;
    rawInsn_div.detail = &rawDetail_div;
    size_t size_div = 4;
    uint64_t address_div = 0;
    const uint8_t* encoding_div =
        reinterpret_cast<const uint8_t*>(divInstrBytes.data());
    cs_disasm_iter(capstoneHandle, &encoding_div, &size_div, &address_div,
                   &rawInsn_div);
    divMetadata = std::make_unique<InstructionMetadata>(rawInsn_div);

    // lbu
    cs_insn rawInsn_lbu;
    cs_detail rawDetail_ldp;
    rawInsn_lbu.detail = &rawDetail_ldp;
    size_t size_lbu = 4;
    uint64_t address_lbu = 0;
    const uint8_t* encoding_lbu =
        reinterpret_cast<const uint8_t*>(lbuInstrBytes.data());
    cs_disasm_iter(capstoneHandle, &encoding_lbu, &size_lbu, &address_lbu,
                   &rawInsn_lbu);
    lbuMetadata = std::make_unique<InstructionMetadata>(rawInsn_lbu);

    // bgeu
    cs_insn rawInsn_bgeu;
    cs_detail rawDetail_bgeu;
    rawInsn_bgeu.detail = &rawDetail_bgeu;
    size_t size_bgeu = 4;
    uint64_t address_bgeu = 0;
    const uint8_t* encoding_bgeu =
        reinterpret_cast<const uint8_t*>(bgeuInstrBytes.data());
    cs_disasm_iter(capstoneHandle, &encoding_bgeu, &size_bgeu, &address_bgeu,
                   &rawInsn_bgeu);
    bgeuMetadata = std::make_unique<InstructionMetadata>(rawInsn_bgeu);

    const uint8_t* badEncoding =
        reinterpret_cast<const uint8_t*>(invalidInstrBytes.data());
    invalidMetadata = std::make_unique<InstructionMetadata>(badEncoding);
  }

  ~RiscVInstructionTest() { cs_close(&capstoneHandle); }

 protected:
  ConfigInit configInit = ConfigInit(config::ISA::RV64, "");

  // div a3, a3, a0
  std::array<uint8_t, 4> divInstrBytes = {0xB3, 0xC6, 0xA6, 0x02};
  // lbu a5, 0(s3)
  std::array<uint8_t, 4> lbuInstrBytes = {0x83, 0xC7, 0x09, 0x00};
  // bgeu a5, a4, -86
  std::array<uint8_t, 4> bgeuInstrBytes = {0xE3, 0xF5, 0xE7, 0xFA};
  std::array<uint8_t, 4> invalidInstrBytes = {0x20, 0x00, 0x02, 0x8c};

  // A Capstone decoding library handle, for decoding instructions.
  csh capstoneHandle;

  kernel::Linux os;
  Architecture arch;

  std::unique_ptr<InstructionMetadata> divMetadata;
  std::unique_ptr<InstructionMetadata> lbuMetadata;
  std::unique_ptr<InstructionMetadata> bgeuMetadata;
  std::unique_ptr<InstructionMetadata> invalidMetadata;
  InstructionException exception;
};

// Test that a valid instruction is created correctly
TEST_F(RiscVInstructionTest, validInsn) {
  // Insn is `div	a3, a3, a0`
  Instruction insn = Instruction(arch, *divMetadata.get());
  // Define instruction's registers
  std::vector<Register> destRegs = {{RegisterType::GENERAL, 13}};
  std::vector<Register> srcRegs = {{RegisterType::GENERAL, 13},
                                   {RegisterType::GENERAL, 10}};
  const std::vector<uint16_t> ports = {1, 2, 3};
  insn.setExecutionInfo({3, 4, ports});
  insn.setInstructionAddress(0x48);
  insn.setInstructionId(11);
  insn.setSequenceId(12);

  // Ensure that all instruction values are as expected after creation
  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred) ? true : false;
  EXPECT_EQ(&insn.getArchitecture(), &arch);
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_TRUE(matchingPred);
  EXPECT_EQ(insn.getBranchType(), BranchType::Unknown);
  EXPECT_EQ(insn.getData().size(), 0);
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs.size());
  for (size_t i = 0; i < destRegs.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs[i]);
  }
  EXPECT_EQ(insn.getException(), InstructionException::None);
  EXPECT_EQ(insn.getGeneratedAddresses().size(), 0);
  EXPECT_EQ(insn.getGroup(), InstructionGroups::INT_DIV_OR_SQRT);
  EXPECT_EQ(insn.getInstructionAddress(), 0x48);
  EXPECT_EQ(insn.getInstructionId(), 11);
  EXPECT_EQ(insn.getKnownOffset(), 0);
  EXPECT_EQ(insn.getLatency(), 3);
  EXPECT_EQ(insn.getLSQLatency(), 1);
  EXPECT_EQ(&insn.getMetadata(), divMetadata.get());
  EXPECT_EQ(insn.getMicroOpIndex(), 0);
  EXPECT_EQ(insn.getResults().size(), 1);
  EXPECT_EQ(insn.getSequenceId(), 12);
  EXPECT_EQ(insn.getSourceOperands().size(), 2);
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs.size());
  for (size_t i = 0; i < srcRegs.size(); i++) {
    EXPECT_EQ(insn.getSourceRegisters()[i], srcRegs[i]);
    EXPECT_FALSE(insn.isOperandReady(i));
  }
  EXPECT_EQ(insn.getStallCycles(), 4);
  EXPECT_EQ(insn.getSupportedPorts(), ports);

  EXPECT_FALSE(insn.canExecute());
  EXPECT_FALSE(insn.isStoreAddress());
  EXPECT_FALSE(insn.isStoreData());
  EXPECT_FALSE(insn.isLoad());
  EXPECT_FALSE(insn.isBranch());
  EXPECT_FALSE(insn.exceptionEncountered());
  EXPECT_FALSE(insn.hasExecuted());
  EXPECT_FALSE(insn.canCommit());
  EXPECT_TRUE(insn.hasAllData());
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.isFlushed());
  EXPECT_FALSE(insn.isMicroOp());
  EXPECT_TRUE(insn.isLastMicroOp());
  EXPECT_FALSE(insn.isWaitingCommit());
}

// Test that an invalid instruction can be created - invalid due to byte stream
TEST_F(RiscVInstructionTest, invalidInsn_1) {
  Instruction insn = Instruction(arch, *invalidMetadata.get());
  // Define instruction's registers
  std::vector<Register> destRegs = {};
  std::vector<Register> srcRegs = {};
  const std::vector<uint16_t> ports = {};
  insn.setExecutionInfo({1, 1, ports});
  insn.setInstructionAddress(0x44);
  insn.setInstructionId(13);
  insn.setSequenceId(14);

  // Ensure that all instruction values are as expected after creation
  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred) ? true : false;
  EXPECT_EQ(&insn.getArchitecture(), &arch);
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_TRUE(matchingPred);
  EXPECT_EQ(insn.getBranchType(), BranchType::Unknown);
  EXPECT_EQ(insn.getData().size(), 0);
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs.size());
  for (size_t i = 0; i < destRegs.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs[i]);
  }
  EXPECT_EQ(insn.getException(), InstructionException::EncodingUnallocated);
  EXPECT_EQ(insn.getGeneratedAddresses().size(), 0);
  // Default Group
  EXPECT_EQ(insn.getGroup(), InstructionGroups::INT_SIMPLE_ARTH);
  EXPECT_EQ(insn.getInstructionAddress(), 0x44);
  EXPECT_EQ(insn.getInstructionId(), 13);
  EXPECT_EQ(insn.getKnownOffset(), 0);
  EXPECT_EQ(insn.getLatency(), 1);
  EXPECT_EQ(insn.getLSQLatency(), 1);
  EXPECT_EQ(&insn.getMetadata(), invalidMetadata.get());
  EXPECT_EQ(insn.getMicroOpIndex(), 0);
  EXPECT_EQ(insn.getResults().size(), 0);
  EXPECT_EQ(insn.getSequenceId(), 14);
  EXPECT_EQ(insn.getSourceOperands().size(), 0);
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs.size());
  for (size_t i = 0; i < srcRegs.size(); i++) {
    EXPECT_EQ(insn.getSourceRegisters()[i], srcRegs[i]);
    EXPECT_FALSE(insn.isOperandReady(i));
  }
  EXPECT_EQ(insn.getStallCycles(), 1);
  EXPECT_EQ(insn.getSupportedPorts(), ports);

  EXPECT_TRUE(insn.canExecute());
  EXPECT_FALSE(insn.isStoreAddress());
  EXPECT_FALSE(insn.isStoreData());
  EXPECT_FALSE(insn.isLoad());
  EXPECT_FALSE(insn.isBranch());
  EXPECT_TRUE(insn.exceptionEncountered());
  EXPECT_FALSE(insn.hasExecuted());
  EXPECT_FALSE(insn.canCommit());
  EXPECT_TRUE(insn.hasAllData());
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.isFlushed());
  EXPECT_FALSE(insn.isMicroOp());
  EXPECT_TRUE(insn.isLastMicroOp());
  EXPECT_FALSE(insn.isWaitingCommit());
}

// Test that an invalid instruction can be created - invalid due to exception
// provided
TEST_F(RiscVInstructionTest, invalidInsn_2) {
  Instruction insn = Instruction(arch, *invalidMetadata.get(),
                                 InstructionException::HypervisorCall);
  // Define instruction's registers
  std::vector<Register> destRegs = {};
  std::vector<Register> srcRegs = {};
  const std::vector<uint16_t> ports = {};
  insn.setExecutionInfo({1, 1, ports});
  insn.setInstructionAddress(0x43);
  insn.setInstructionId(15);
  insn.setSequenceId(16);

  // Ensure that all instruction values are as expected after creation
  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred) ? true : false;
  EXPECT_EQ(&insn.getArchitecture(), &arch);
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_TRUE(matchingPred);
  EXPECT_EQ(insn.getBranchType(), BranchType::Unknown);
  EXPECT_EQ(insn.getData().size(), 0);
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs.size());
  for (size_t i = 0; i < destRegs.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs[i]);
  }
  EXPECT_EQ(insn.getException(), InstructionException::HypervisorCall);
  EXPECT_EQ(insn.getGeneratedAddresses().size(), 0);
  // Default Group
  EXPECT_EQ(insn.getGroup(), InstructionGroups::INT_SIMPLE_ARTH);
  EXPECT_EQ(insn.getInstructionAddress(), 0x43);
  EXPECT_EQ(insn.getInstructionId(), 15);
  EXPECT_EQ(insn.getKnownOffset(), 0);
  EXPECT_EQ(insn.getLatency(), 1);
  EXPECT_EQ(insn.getLSQLatency(), 1);
  EXPECT_EQ(&insn.getMetadata(), invalidMetadata.get());
  EXPECT_EQ(insn.getMicroOpIndex(), 0);
  EXPECT_EQ(insn.getResults().size(), 0);
  EXPECT_EQ(insn.getSequenceId(), 16);
  EXPECT_EQ(insn.getSourceOperands().size(), 0);
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs.size());
  for (size_t i = 0; i < srcRegs.size(); i++) {
    EXPECT_EQ(insn.getSourceRegisters()[i], srcRegs[i]);
    EXPECT_FALSE(insn.isOperandReady(i));
  }
  EXPECT_EQ(insn.getStallCycles(), 1);
  EXPECT_EQ(insn.getSupportedPorts(), ports);

  EXPECT_TRUE(insn.canExecute());
  EXPECT_FALSE(insn.isStoreAddress());
  EXPECT_FALSE(insn.isStoreData());
  EXPECT_FALSE(insn.isLoad());
  EXPECT_FALSE(insn.isBranch());
  EXPECT_TRUE(insn.exceptionEncountered());
  EXPECT_FALSE(insn.hasExecuted());
  EXPECT_FALSE(insn.canCommit());
  EXPECT_TRUE(insn.hasAllData());
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.isFlushed());
  EXPECT_FALSE(insn.isMicroOp());
  EXPECT_TRUE(insn.isLastMicroOp());
  EXPECT_FALSE(insn.isWaitingCommit());
}

// Test to ensure that source and operand registers can be renamed correctly
TEST_F(RiscVInstructionTest, renameRegs) {
  // Insn is `div	a3, a3, a0`
  Instruction insn = Instruction(arch, *divMetadata.get());
  // Define instruction's registers
  std::vector<Register> destRegs = {{RegisterType::GENERAL, 13}};
  std::vector<Register> srcRegs = {{RegisterType::GENERAL, 13},
                                   {RegisterType::GENERAL, 10}};
  // Ensure registers decoded correctly
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs.size());
  for (size_t i = 0; i < srcRegs.size(); i++) {
    EXPECT_EQ(insn.getSourceRegisters()[i], srcRegs[i]);
  }
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs.size());
  for (size_t i = 0; i < destRegs.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs[i]);
  }

  // Define renamed registers
  std::vector<Register> destRegs_new = {{RegisterType::GENERAL, 24}};
  std::vector<Register> srcRegs_new = {{RegisterType::GENERAL, 13},
                                       {RegisterType::GENERAL, 97}};
  insn.renameDestination(0, destRegs_new[0]);
  insn.renameSource(1, srcRegs_new[1]);
  // Ensure renaming functionality works as expected
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs_new.size());
  for (size_t i = 0; i < srcRegs_new.size(); i++) {
    EXPECT_EQ(insn.getSourceRegisters()[i], srcRegs_new[i]);
  }
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs_new.size());
  for (size_t i = 0; i < destRegs_new.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs_new[i]);
  }
}

// Test that operand values can be properly supplied and change the state of
// `canExecute`
TEST_F(RiscVInstructionTest, supplyOperand) {
  // Insn is `div	a3, a3, a0`
  Instruction insn = Instruction(arch, *divMetadata.get());
  // Define instruction's registers
  std::vector<Register> destRegs = {{RegisterType::GENERAL, 13}};
  std::vector<Register> srcRegs = {{RegisterType::GENERAL, 13},
                                   {RegisterType::GENERAL, 10}};
  // Check initial state is as expected
  EXPECT_FALSE(insn.canExecute());
  EXPECT_FALSE(insn.isOperandReady(0));
  EXPECT_FALSE(insn.isOperandReady(1));

  // Define mock register values for source registers
  RegisterValue val = {0xABBACAFE, 8};
  // Supply values for all source registers
  insn.supplyOperand(0, val);
  insn.supplyOperand(1, val);
  // Ensure Instruction state has updated as expected
  EXPECT_TRUE(insn.canExecute());
  EXPECT_TRUE(insn.isOperandReady(0));
  EXPECT_TRUE(insn.isOperandReady(1));
  auto sourceVals = insn.getSourceOperands();
  EXPECT_EQ(sourceVals.size(), 2);
  EXPECT_EQ(sourceVals[0], val);
  EXPECT_EQ(sourceVals[1], val);

  // Ensure instruction execute updates instruction state as expected, and
  // produces the expected result.
  EXPECT_FALSE(insn.hasExecuted());
  insn.execute();
  EXPECT_TRUE(insn.hasExecuted());
  auto results = insn.getResults();
  RegisterValue refRes = {0x00000001, 8};
  EXPECT_EQ(results.size(), 1);
  EXPECT_EQ(results[0], refRes);
}

// Test that data can be supplied successfully
TEST_F(RiscVInstructionTest, supplyData) {
  // Insn is `lbu	a5, 0(s3)`
  Instruction insn = Instruction(arch, *lbuMetadata.get());
  // Define instruction's registers
  std::vector<Register> destRegs = {{RegisterType::GENERAL, 15}};
  std::vector<Register> srcRegs = {{RegisterType::GENERAL, 19}};

  // Check instruction created correctly
  EXPECT_FALSE(insn.exceptionEncountered());
  EXPECT_EQ(&insn.getMetadata(), lbuMetadata.get());
  EXPECT_EQ(insn.getGroup(), InstructionGroups::LOAD_INT);

  // Check source and destination registers extracted correctly
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs.size());
  for (size_t i = 0; i < srcRegs.size(); i++) {
    EXPECT_EQ(insn.getSourceRegisters()[i], srcRegs[i]);
  }
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs.size());
  for (size_t i = 0; i < destRegs.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs[i]);
  }

  // Supply needed operands
  EXPECT_FALSE(insn.isOperandReady(0));
  RegisterValue addr = {0x480, 8};
  insn.supplyOperand(0, addr);
  EXPECT_TRUE(insn.isOperandReady(0));

  // Generate memory addresses
  EXPECT_EQ(insn.getGeneratedAddresses().size(), 0);
  insn.generateAddresses();
  auto generatedAddresses = insn.getGeneratedAddresses();
  EXPECT_EQ(generatedAddresses.size(), 1);
  EXPECT_EQ(generatedAddresses[0].address, 0x480);
  EXPECT_EQ(generatedAddresses[0].size, 1);

  // Supply required data
  EXPECT_FALSE(insn.hasAllData());
  std::vector<RegisterValue> data = {{123, 1}};
  EXPECT_EQ(generatedAddresses.size(), data.size());
  insn.supplyData(generatedAddresses[0].address, data[0]);
  // Ensure data was supplied correctly
  auto retrievedData = insn.getData();
  for (size_t i = 0; i < retrievedData.size(); i++) {
    EXPECT_EQ(retrievedData[i], data[i]);
  }
  EXPECT_TRUE(insn.hasAllData());
}

// Test DataAbort Exception is triggered correctly when supplying data
TEST_F(RiscVInstructionTest, supplyData_dataAbort) {
  // Insn is `lbu	a5, 0(s3)`
  Instruction insn = Instruction(arch, *lbuMetadata.get());
  // Define instruction's registers
  std::vector<Register> destRegs = {{RegisterType::GENERAL, 15}};
  std::vector<Register> srcRegs = {{RegisterType::GENERAL, 19}};

  // Check instruction created correctly
  EXPECT_EQ(&insn.getMetadata(), lbuMetadata.get());
  EXPECT_EQ(insn.getGroup(), InstructionGroups::LOAD_INT);

  // Supply needed operands
  EXPECT_FALSE(insn.isOperandReady(0));
  RegisterValue addr = {0x480, 8};
  insn.supplyOperand(0, addr);
  EXPECT_TRUE(insn.isOperandReady(0));

  // Generate memory addresses
  EXPECT_EQ(insn.getGeneratedAddresses().size(), 0);
  insn.generateAddresses();
  auto generatedAddresses = insn.getGeneratedAddresses();
  EXPECT_EQ(generatedAddresses.size(), 1);
  EXPECT_EQ(generatedAddresses[0].address, 0x480);
  EXPECT_EQ(generatedAddresses[0].size, 1);

  // Trigger data abort
  EXPECT_FALSE(insn.exceptionEncountered());
  insn.supplyData(generatedAddresses[0].address, RegisterValue());
  EXPECT_TRUE(insn.exceptionEncountered());
  EXPECT_EQ(insn.getException(), InstructionException::DataAbort);
}

// Test to check logic around early branch misprediction logic
TEST_F(RiscVInstructionTest, earlyBranchMisprediction) {
  // Insn is `div	a3, a3, a0`
  Instruction insn = Instruction(arch, *divMetadata.get());
  insn.setInstructionAddress(64);

  // Check initial state of an instruction's branch related options
  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Unknown);
  EXPECT_FALSE(insn.isBranch());
  std::tuple<bool, uint64_t> tup = {false, insn.getInstructionAddress() + 4};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);

  // Set prediction and ensure expected state changes / outcomes are seen
  pred = {true, 0x4848};
  insn.setBranchPrediction(pred);
  matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Unknown);
  // Check logic of `checkEarlyBranchMisprediction` which is different for
  // non-branch instructions
  EXPECT_FALSE(insn.isBranch());
  tup = {true, insn.getInstructionAddress() + 4};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);
}

// Test that a correct prediction (branch taken) is handled correctly
TEST_F(RiscVInstructionTest, correctPred_taken) {
  // insn is `bgeu a5, a4, -86`
  Instruction insn = Instruction(arch, *bgeuMetadata.get());
  insn.setInstructionAddress(400);

  // Check initial state of an instruction's branch related options
  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Conditional);
  EXPECT_TRUE(insn.isBranch());
  std::tuple<bool, uint64_t> tup = {false, 0};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);

  // Test a correct prediction where branch is taken is handled correctly
  pred = {true, 400 - 86};
  insn.setBranchPrediction(pred);
  matchingPred = (insn.getBranchPrediction() == pred);
  insn.supplyOperand(0, RegisterValue(3, 8));
  insn.supplyOperand(1, RegisterValue(0, 8));
  insn.execute();
  EXPECT_TRUE(matchingPred);
  EXPECT_TRUE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), pred.target);
}

// Test that a correct prediction (branch not taken) is handled correctly
TEST_F(RiscVInstructionTest, correctPred_notTaken) {
  // insn is `bgeu a5, a4, -86`
  Instruction insn = Instruction(arch, *bgeuMetadata.get());
  insn.setInstructionAddress(400);

  // Check initial state of an instruction's branch related options
  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Conditional);
  EXPECT_TRUE(insn.isBranch());
  std::tuple<bool, uint64_t> tup = {false, 0};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);

  // Test a correct prediction where a branch isn't taken is handled correctly
  // imm operand 0x28 has 4 added implicitly by dissassembler
  pred = {false, 400 + 4};
  insn.setBranchPrediction(pred);
  matchingPred = (insn.getBranchPrediction() == pred);
  insn.supplyOperand(0, RegisterValue(0, 8));
  insn.supplyOperand(1, RegisterValue(3, 8));
  insn.execute();
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), pred.target);
}

// Test that an incorrect prediction (wrong target) is handled correctly
TEST_F(RiscVInstructionTest, incorrectPred_target) {
  // insn is `bgeu a5, a4, -86`
  Instruction insn = Instruction(arch, *bgeuMetadata.get());
  insn.setInstructionAddress(400);

  // Check initial state of an instruction's branch related options
  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Conditional);
  EXPECT_TRUE(insn.isBranch());
  std::tuple<bool, uint64_t> tup = {false, 0};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);

  // Test an incorrect prediction is handled correctly - target is wrong
  // imm operand 0x28 has 4 added implicitly by dissassembler
  pred = {true, 80 + (0x28 + 0x4)};
  insn.setBranchPrediction(pred);
  matchingPred = (insn.getBranchPrediction() == pred);
  insn.supplyOperand(0, RegisterValue(3, 8));
  insn.supplyOperand(1, RegisterValue(0, 8));
  insn.execute();
  EXPECT_TRUE(matchingPred);
  EXPECT_TRUE(insn.wasBranchTaken());
  EXPECT_TRUE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), 400 - 86);
}

// Test that an incorrect prediction (wrong taken) is handled correctly
TEST_F(RiscVInstructionTest, incorrectPred_taken) {
  // insn is `bgeu a5, a4, -86`
  Instruction insn = Instruction(arch, *bgeuMetadata.get());
  insn.setInstructionAddress(400);

  // Check initial state of an instruction's branch related options
  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Conditional);
  EXPECT_TRUE(insn.isBranch());
  std::tuple<bool, uint64_t> tup = {false, 0};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);

  // Test an incorrect prediction is handled correctly - taken is wrong
  // imm operand 0x28 has 4 added implicitly by dissassembler
  pred = {true, 400 - 86};
  insn.setBranchPrediction(pred);
  matchingPred = (insn.getBranchPrediction() == pred);
  insn.supplyOperand(0, RegisterValue(0, 8));
  insn.supplyOperand(1, RegisterValue(3, 8));
  insn.execute();
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_TRUE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), 400 + 4);
}

// Test commit and flush setters such as `setFlushed`, `setCommitReady`, etc.
TEST_F(RiscVInstructionTest, setters) {
  // Insn is `div	a3, a3, a0`
  Instruction insn = Instruction(arch, *divMetadata.get());

  EXPECT_FALSE(insn.canCommit());
  insn.setCommitReady();
  EXPECT_TRUE(insn.canCommit());

  EXPECT_FALSE(insn.isFlushed());
  insn.setFlushed();
  EXPECT_TRUE(insn.isFlushed());

  EXPECT_FALSE(insn.isWaitingCommit());
  insn.setWaitingCommit();
  EXPECT_TRUE(insn.isWaitingCommit());
}

/** Tests that the printInstruction() function works correctly. */
TEST_F(RiscVInstructionTest, printInstruction) {
  // Insn is `div	a3, a3, a0`
  Instruction insn = Instruction(arch, *divMetadata.get());

  testing::internal::CaptureStdout();
  insn.printInstruction();
  EXPECT_THAT(testing::internal::GetCapturedStdout(),
              testing::HasSubstr("div a3, a3, a0"));
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng