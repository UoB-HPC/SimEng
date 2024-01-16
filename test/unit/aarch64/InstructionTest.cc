#include "../ConfigInit.hh"
#include "../MockArchitecture.hh"
#include "arch/aarch64/InstructionMetadata.hh"
#include "gmock/gmock.h"
#include "simeng/arch/aarch64/Instruction.hh"
#include "simeng/version.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

// AArch64 Instruction Tests
class AArch64InstructionTest : public testing::Test {
 public:
  AArch64InstructionTest()
      : os(config::SimInfo::getConfig()["CPU-Info"]["Special-File-Dir-Path"]
               .as<std::string>()),
        arch(os) {
    // Create InstructionMetadata objects
    cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &capstoneHandle);
    cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);

    // fdiv
    cs_insn rawInsn_fdiv;
    cs_detail rawDetail_fdiv;
    rawInsn_fdiv.detail = &rawDetail_fdiv;
    size_t size_fdiv = 4;
    uint64_t address_fdiv = 0;
    const uint8_t* encoding_fdiv =
        reinterpret_cast<const uint8_t*>(fdivInstrBytes.data());
    cs_disasm_iter(capstoneHandle, &encoding_fdiv, &size_fdiv, &address_fdiv,
                   &rawInsn_fdiv);
    fdivMetadata = std::make_unique<InstructionMetadata>(rawInsn_fdiv);

    // ldp
    cs_insn rawInsn_ldp;
    cs_detail rawDetail_ldp;
    rawInsn_ldp.detail = &rawDetail_ldp;
    size_t size_ldp = 4;
    uint64_t address_ldp = 4;
    const uint8_t* encoding_ldp =
        reinterpret_cast<const uint8_t*>(ldpInstrBytes.data());
    cs_disasm_iter(capstoneHandle, &encoding_ldp, &size_ldp, &address_ldp,
                   &rawInsn_ldp);
    ldpMetadata = std::make_unique<InstructionMetadata>(rawInsn_ldp);

    // cbz
    cs_insn rawInsn_cbz;
    cs_detail rawDetail_cbz;
    rawInsn_cbz.detail = &rawDetail_cbz;
    size_t size_cbz = 4;
    uint64_t address_cbz = 4;
    const uint8_t* encoding_cbz =
        reinterpret_cast<const uint8_t*>(cbzInstrBytes.data());
    cs_disasm_iter(capstoneHandle, &encoding_cbz, &size_cbz, &address_cbz,
                   &rawInsn_cbz);
    cbzMetadata = std::make_unique<InstructionMetadata>(rawInsn_cbz);

    const uint8_t* badEncoding =
        reinterpret_cast<const uint8_t*>(invalidInstrBytes.data());
    invalidMetadata = std::make_unique<InstructionMetadata>(badEncoding);
  }

  ~AArch64InstructionTest() { cs_close(&capstoneHandle); }

 protected:
  ConfigInit configInit = ConfigInit(config::ISA::AArch64, "");

  // fdivr z1.s, p0/m, z1.s, z0.s
  std::array<uint8_t, 4> fdivInstrBytes = {0x01, 0x80, 0x8c, 0x65};
  // ldp x1, x2, [x3]
  std::array<uint8_t, 4> ldpInstrBytes = {0x61, 0x08, 0x40, 0xA9};
  // cbz x2, #0x28
  std::array<uint8_t, 4> cbzInstrBytes = {0x42, 0x01, 0x00, 0xB4};
  std::array<uint8_t, 4> invalidInstrBytes = {0x20, 0x00, 0x02, 0x8c};

  // A Capstone decoding library handle, for decoding instructions.
  csh capstoneHandle;

  kernel::Linux os;
  Architecture arch;

  std::unique_ptr<InstructionMetadata> fdivMetadata;
  std::unique_ptr<InstructionMetadata> ldpMetadata;
  std::unique_ptr<InstructionMetadata> cbzMetadata;
  std::unique_ptr<InstructionMetadata> invalidMetadata;
  std::unique_ptr<MicroOpInfo> uopInfo;
  InstructionException exception;
};

// Test that a valid instruction is created correctly
TEST_F(AArch64InstructionTest, validInsn) {
  // Insn is `fdivr z1.s, p0/m, z1.s, z0.s`
  Instruction insn = Instruction(arch, *fdivMetadata.get(), MicroOpInfo());
  std::vector<Register> destRegs = {{RegisterType::VECTOR, 1}};
  std::vector<Register> srcRegs = {{RegisterType::PREDICATE, 0},
                                   {RegisterType::VECTOR, 1},
                                   {RegisterType::VECTOR, 0}};
  const std::vector<uint16_t> ports = {1, 2, 3};
  insn.setExecutionInfo({3, 3, ports});
  insn.setInstructionAddress(0x48);
  insn.setInstructionId(11);
  insn.setSequenceId(12);

  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred) ? true : false;
  EXPECT_EQ(&insn.getArchitecture(), &arch);
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_TRUE(matchingPred);
  EXPECT_EQ(insn.getBranchType(), BranchType::Unknown);
  EXPECT_EQ(insn.getData().size(), 0);
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs.size());
  for (int i = 0; i < destRegs.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs[i]);
  }
  EXPECT_EQ(insn.getException(), InstructionException::None);
  EXPECT_EQ(insn.getGeneratedAddresses().size(), 0);
  EXPECT_EQ(insn.getGroup(), InstructionGroups::SVE_DIV_OR_SQRT);
  EXPECT_EQ(insn.getInstructionAddress(), 0x48);
  EXPECT_EQ(insn.getInstructionId(), 11);
  EXPECT_EQ(insn.getKnownOffset(), 0);
  EXPECT_EQ(insn.getLatency(), 3);
  EXPECT_EQ(insn.getLSQLatency(), 1);
  EXPECT_EQ(&insn.getMetadata(), fdivMetadata.get());
  EXPECT_EQ(insn.getMicroOpIndex(), 0);
  // Results vector resized at decode
  EXPECT_EQ(insn.getResults().size(), 1);
  EXPECT_EQ(insn.getSequenceId(), 12);
  // Operands vector resized at decode
  EXPECT_EQ(insn.getSourceOperands().size(), 3);
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs.size());
  for (int i = 0; i < srcRegs.size(); i++) {
    EXPECT_EQ(insn.getSourceRegisters()[i], srcRegs[i]);
    EXPECT_FALSE(insn.isOperandReady(i));
  }
  EXPECT_EQ(insn.getStallCycles(), 3);
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
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.isFlushed());
  EXPECT_FALSE(insn.isMicroOp());
  EXPECT_TRUE(insn.isLastMicroOp());
  EXPECT_FALSE(insn.isWaitingCommit());
}

// Test that an invalid instruction can be created - invalid due to byte stream
TEST_F(AArch64InstructionTest, invalidInsn_1) {
  Instruction insn = Instruction(arch, *invalidMetadata.get(), MicroOpInfo());
  std::vector<Register> destRegs = {};
  std::vector<Register> srcRegs = {};
  const std::vector<uint16_t> ports = {};
  insn.setExecutionInfo({1, 1, ports});
  insn.setInstructionAddress(0x44);
  insn.setInstructionId(13);
  insn.setSequenceId(14);

  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred) ? true : false;
  EXPECT_EQ(&insn.getArchitecture(), &arch);
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_TRUE(matchingPred);
  EXPECT_EQ(insn.getBranchType(), BranchType::Unknown);
  EXPECT_EQ(insn.getData().size(), 0);
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs.size());
  for (int i = 0; i < destRegs.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs[i]);
  }
  EXPECT_EQ(insn.getException(), InstructionException::EncodingUnallocated);
  EXPECT_EQ(insn.getGeneratedAddresses().size(), 0);
  // Default Group
  EXPECT_EQ(insn.getGroup(), InstructionGroups::INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_EQ(insn.getInstructionAddress(), 0x44);
  EXPECT_EQ(insn.getInstructionId(), 13);
  EXPECT_EQ(insn.getKnownOffset(), 0);
  EXPECT_EQ(insn.getLatency(), 1);
  EXPECT_EQ(insn.getLSQLatency(), 1);
  EXPECT_EQ(&insn.getMetadata(), invalidMetadata.get());
  EXPECT_EQ(insn.getMicroOpIndex(), 0);
  // Results vector resized at decode
  EXPECT_EQ(insn.getResults().size(), 0);
  EXPECT_EQ(insn.getSequenceId(), 14);
  // Operands vector resized at decode
  EXPECT_EQ(insn.getSourceOperands().size(), 0);
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs.size());
  for (int i = 0; i < srcRegs.size(); i++) {
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
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.isFlushed());
  EXPECT_FALSE(insn.isMicroOp());
  EXPECT_TRUE(insn.isLastMicroOp());
  EXPECT_FALSE(insn.isWaitingCommit());
}

// Test that an invalid instruction can be created - invalid due to exception
// provided
TEST_F(AArch64InstructionTest, invalidInsn_2) {
  Instruction insn = Instruction(arch, *invalidMetadata.get(),
                                 InstructionException::HypervisorCall);

  std::vector<Register> destRegs = {};
  std::vector<Register> srcRegs = {};
  const std::vector<uint16_t> ports = {};
  insn.setExecutionInfo({1, 1, ports});
  insn.setInstructionAddress(0x43);
  insn.setInstructionId(15);
  insn.setSequenceId(16);

  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred) ? true : false;
  EXPECT_EQ(&insn.getArchitecture(), &arch);
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_TRUE(matchingPred);
  EXPECT_EQ(insn.getBranchType(), BranchType::Unknown);
  EXPECT_EQ(insn.getData().size(), 0);
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs.size());
  for (int i = 0; i < destRegs.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs[i]);
  }
  EXPECT_EQ(insn.getException(), InstructionException::HypervisorCall);
  EXPECT_EQ(insn.getGeneratedAddresses().size(), 0);
  // Default Group
  EXPECT_EQ(insn.getGroup(), InstructionGroups::INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_EQ(insn.getInstructionAddress(), 0x43);
  EXPECT_EQ(insn.getInstructionId(), 15);
  EXPECT_EQ(insn.getKnownOffset(), 0);
  EXPECT_EQ(insn.getLatency(), 1);
  EXPECT_EQ(insn.getLSQLatency(), 1);
  EXPECT_EQ(&insn.getMetadata(), invalidMetadata.get());
  EXPECT_EQ(insn.getMicroOpIndex(), 0);
  // Results vector resized at decode
  EXPECT_EQ(insn.getResults().size(), 0);
  EXPECT_EQ(insn.getSequenceId(), 16);
  // Operands vector resized at decode
  EXPECT_EQ(insn.getSourceOperands().size(), 0);
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs.size());
  for (int i = 0; i < srcRegs.size(); i++) {
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
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.isFlushed());
  EXPECT_FALSE(insn.isMicroOp());
  EXPECT_TRUE(insn.isLastMicroOp());
  EXPECT_FALSE(insn.isWaitingCommit());
}

// Test to ensure that source and operand registers can be renamed correctly
TEST_F(AArch64InstructionTest, renameRegs) {
  // Insn is `fdivr z1.s, p0/m, z1.s, z0.s`
  Instruction insn = Instruction(arch, *fdivMetadata.get(), MicroOpInfo());
  std::vector<Register> destRegs = {{RegisterType::VECTOR, 1}};
  std::vector<Register> srcRegs = {{RegisterType::PREDICATE, 0},
                                   {RegisterType::VECTOR, 1},
                                   {RegisterType::VECTOR, 0}};
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs.size());
  for (int i = 0; i < srcRegs.size(); i++) {
    EXPECT_EQ(insn.getSourceRegisters()[i], srcRegs[i]);
  }
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs.size());
  for (int i = 0; i < destRegs.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs[i]);
  }

  std::vector<Register> destRegs_new = {{RegisterType::VECTOR, 24}};
  std::vector<Register> srcRegs_new = {{RegisterType::PREDICATE, 0},
                                       {RegisterType::VECTOR, 97},
                                       {RegisterType::VECTOR, 0}};
  insn.renameDestination(0, destRegs_new[0]);
  insn.renameSource(1, srcRegs_new[1]);
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs_new.size());
  for (int i = 0; i < srcRegs_new.size(); i++) {
    EXPECT_EQ(insn.getSourceRegisters()[i], srcRegs_new[i]);
  }
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs_new.size());
  for (int i = 0; i < destRegs_new.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs_new[i]);
  }
}

// Test that operand values can be properly supplied and change the state of
// `canExecute`
TEST_F(AArch64InstructionTest, supplyOperand) {
  // Insn is `fdivr z1.s, p0/m, z1.s, z0.s`
  Instruction insn = Instruction(arch, *fdivMetadata.get(), MicroOpInfo());
  std::vector<Register> destRegs = {{RegisterType::VECTOR, 1}};
  std::vector<Register> srcRegs = {{RegisterType::PREDICATE, 0},
                                   {RegisterType::VECTOR, 1},
                                   {RegisterType::VECTOR, 0}};
  EXPECT_FALSE(insn.canExecute());
  EXPECT_FALSE(insn.isOperandReady(0));
  EXPECT_FALSE(insn.isOperandReady(1));
  EXPECT_FALSE(insn.isOperandReady(2));

  RegisterValue vec = {0xABBACAFE01234567, 256};
  RegisterValue pred = {0xFFFFFFFF, 32};
  insn.supplyOperand(0, pred);
  insn.supplyOperand(1, vec);
  insn.supplyOperand(2, vec);
  EXPECT_TRUE(insn.canExecute());
  EXPECT_TRUE(insn.isOperandReady(0));
  EXPECT_TRUE(insn.isOperandReady(1));
  EXPECT_TRUE(insn.isOperandReady(2));
  auto sourceVals = insn.getSourceOperands();
  EXPECT_EQ(sourceVals.size(), 3);
  EXPECT_EQ(sourceVals[0], pred);
  EXPECT_EQ(sourceVals[1], vec);
  EXPECT_EQ(sourceVals[2], vec);

  EXPECT_FALSE(insn.hasExecuted());
  insn.execute();
  EXPECT_TRUE(insn.hasExecuted());
  auto results = insn.getResults();
  RegisterValue refRes = {0x0000000100000001, 256};
  EXPECT_EQ(results.size(), 1);
  EXPECT_EQ(results[0], refRes);
}

// Test that data can be supplied successfully
TEST_F(AArch64InstructionTest, supplyData) {
  // Insn is `ldp x1, x2, [x3]`
  Instruction insn = Instruction(arch, *ldpMetadata.get(), MicroOpInfo());
  std::vector<Register> destRegs = {{RegisterType::GENERAL, 1},
                                    {RegisterType::GENERAL, 2}};
  std::vector<Register> srcRegs = {{RegisterType::GENERAL, 3}};

  // Check instruction created correctly
  EXPECT_FALSE(insn.exceptionEncountered());
  EXPECT_EQ(&insn.getMetadata(), ldpMetadata.get());
  EXPECT_EQ(insn.getGroup(), InstructionGroups::LOAD_INT);

  // Check source and destination registers extracted correctly
  EXPECT_EQ(insn.getSourceRegisters().size(), srcRegs.size());
  for (int i = 0; i < srcRegs.size(); i++) {
    EXPECT_EQ(insn.getSourceRegisters()[i], srcRegs[i]);
  }
  EXPECT_EQ(insn.getDestinationRegisters().size(), destRegs.size());
  for (int i = 0; i < destRegs.size(); i++) {
    EXPECT_EQ(insn.getDestinationRegisters()[i], destRegs[i]);
  }

  // Supply needed operands
  EXPECT_FALSE(insn.isOperandReady(0));
  RegisterValue addr = {0x480, 4};
  insn.supplyOperand(0, addr);
  EXPECT_TRUE(insn.isOperandReady(0));

  // Generate memory addresses
  EXPECT_EQ(insn.getGeneratedAddresses().size(), 0);
  insn.generateAddresses();
  auto generatedAddresses = insn.getGeneratedAddresses();
  EXPECT_EQ(generatedAddresses.size(), 2);
  for (int i = 0; i < generatedAddresses.size(); i++) {
    EXPECT_EQ(generatedAddresses[i].address, 0x480 + (i * 0x8));
    EXPECT_EQ(generatedAddresses[i].size, 8);
  }

  // Supply required data
  EXPECT_FALSE(insn.hasAllData());
  std::vector<RegisterValue> data = {{123, 8}, {456, 8}};
  EXPECT_EQ(generatedAddresses.size(), data.size());
  for (int i = 0; i < generatedAddresses.size(); i++) {
    insn.supplyData(generatedAddresses[i].address, data[i]);
  }
  auto retrievedData = insn.getData();
  for (int i = 0; i < retrievedData.size(); i++) {
    EXPECT_EQ(retrievedData[i], data[i]);
  }
  EXPECT_TRUE(insn.hasAllData());
}

// Test DataAbort Exception is triggered correctly when supplying data
TEST_F(AArch64InstructionTest, supplyData_dataAbort) {
  // Insn is `ldp x1, x2, [x3]`
  Instruction insn = Instruction(arch, *ldpMetadata.get(), MicroOpInfo());
  std::vector<Register> destRegs = {{RegisterType::GENERAL, 1},
                                    {RegisterType::GENERAL, 2}};
  std::vector<Register> srcRegs = {{RegisterType::GENERAL, 3}};

  // Check instruction created correctly
  EXPECT_EQ(&insn.getMetadata(), ldpMetadata.get());
  EXPECT_EQ(insn.getGroup(), InstructionGroups::LOAD_INT);

  // Supply needed operands
  EXPECT_FALSE(insn.isOperandReady(0));
  RegisterValue addr = {0x480, 4};
  insn.supplyOperand(0, addr);
  EXPECT_TRUE(insn.isOperandReady(0));

  // Generate memory addresses
  EXPECT_EQ(insn.getGeneratedAddresses().size(), 0);
  insn.generateAddresses();
  auto generatedAddresses = insn.getGeneratedAddresses();
  EXPECT_EQ(generatedAddresses.size(), 2);
  for (int i = 0; i < generatedAddresses.size(); i++) {
    EXPECT_EQ(generatedAddresses[i].address, 0x480 + (i * 0x8));
    EXPECT_EQ(generatedAddresses[i].size, 8);
  }

  // Trigger data abort
  EXPECT_FALSE(insn.exceptionEncountered());
  insn.supplyData(generatedAddresses[0].address, RegisterValue());
  EXPECT_TRUE(insn.exceptionEncountered());
  EXPECT_EQ(insn.getException(), InstructionException::DataAbort);
}

// Test to check logic around branch misprediction logic
TEST_F(AArch64InstructionTest, branchMisprediction) {
  // Insn is `fdivr z1.s, p0/m, z1.s, z0.s`
  Instruction insn = Instruction(arch, *fdivMetadata.get(), MicroOpInfo());
  insn.setInstructionAddress(64);

  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Unknown);
  EXPECT_FALSE(insn.isBranch());
  std::tuple<bool, uint64_t> tup = {false, insn.getInstructionAddress() + 4};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);

  pred = {true, 0x4848};
  insn.setBranchPrediction(pred);
  matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_TRUE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Unknown);

  EXPECT_FALSE(insn.isBranch());
  tup = {true, insn.getInstructionAddress() + 4};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);
}

TEST_F(AArch64InstructionTest, correctPred_taken) {
  // insn is `cbz x2, #0x28`
  Instruction insn = Instruction(arch, *cbzMetadata.get(), MicroOpInfo());
  insn.setInstructionAddress(80);

  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Conditional);
  EXPECT_TRUE(insn.isBranch());
  std::tuple<bool, uint64_t> tup = {false, 0};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);

  // imm operand 0x28 has 4 added implicitly by dissassembler
  pred = {true, 80 + (0x28 + 0x4)};
  insn.setBranchPrediction(pred);
  matchingPred = (insn.getBranchPrediction() == pred);
  insn.supplyOperand(0, RegisterValue(0, 8));
  insn.execute();
  EXPECT_TRUE(matchingPred);
  EXPECT_TRUE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), pred.target);
}

TEST_F(AArch64InstructionTest, correctPred_notTaken) {
  // insn is `cbz x2, #0x28`
  Instruction insn = Instruction(arch, *cbzMetadata.get(), MicroOpInfo());
  insn.setInstructionAddress(80);

  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Conditional);
  EXPECT_TRUE(insn.isBranch());
  std::tuple<bool, uint64_t> tup = {false, 0};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);

  // imm operand 0x28 has 4 added implicitly by dissassembler
  pred = {false, 80 + 4};
  insn.setBranchPrediction(pred);
  matchingPred = (insn.getBranchPrediction() == pred);
  insn.supplyOperand(0, RegisterValue(1, 8));
  insn.execute();
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), pred.target);
}

TEST_F(AArch64InstructionTest, incorrectPred_target) {
  // insn is `cbz x2, #0x28`
  Instruction insn = Instruction(arch, *cbzMetadata.get(), MicroOpInfo());
  insn.setInstructionAddress(100);

  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Conditional);
  EXPECT_TRUE(insn.isBranch());
  std::tuple<bool, uint64_t> tup = {false, 0};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);

  // imm operand 0x28 has 4 added implicitly by dissassembler
  pred = {true, 80 + (0x28 + 0x4)};
  insn.setBranchPrediction(pred);
  matchingPred = (insn.getBranchPrediction() == pred);
  insn.supplyOperand(0, RegisterValue(0, 8));
  insn.execute();
  EXPECT_TRUE(matchingPred);
  EXPECT_TRUE(insn.wasBranchTaken());
  EXPECT_TRUE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), 100 + (0x28 + 4));
}

TEST_F(AArch64InstructionTest, incorrectPred_taken) {
  // insn is `cbz x2, #0x28`
  Instruction insn = Instruction(arch, *cbzMetadata.get(), MicroOpInfo());
  insn.setInstructionAddress(100);

  BranchPrediction pred = {false, 0};
  bool matchingPred = (insn.getBranchPrediction() == pred);
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_FALSE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), 0);
  EXPECT_EQ(insn.getBranchType(), BranchType::Conditional);
  EXPECT_TRUE(insn.isBranch());
  std::tuple<bool, uint64_t> tup = {false, 0};
  EXPECT_EQ(insn.checkEarlyBranchMisprediction(), tup);

  // imm operand 0x28 has 4 added implicitly by dissassembler
  pred = {true, 100 + (0x28 + 0x4)};
  insn.setBranchPrediction(pred);
  matchingPred = (insn.getBranchPrediction() == pred);
  insn.supplyOperand(0, RegisterValue(1, 8));
  insn.execute();
  EXPECT_TRUE(matchingPred);
  EXPECT_FALSE(insn.wasBranchTaken());
  EXPECT_TRUE(insn.wasBranchMispredicted());
  EXPECT_EQ(insn.getBranchAddress(), 100 + 4);
}

// Test commit and flush setters such as `setFlushed`, `setCommitReady`, etc.
TEST_F(AArch64InstructionTest, setters) {
  // Insn is `fdivr z1.s, p0/m, z1.s, z0.s`
  Instruction insn = Instruction(arch, *fdivMetadata.get(), MicroOpInfo());

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

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng