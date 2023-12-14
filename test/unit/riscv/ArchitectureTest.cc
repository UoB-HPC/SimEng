#include <iostream>

#include "gtest/gtest.h"
#include "simeng/CoreInstance.hh"
#include "simeng/ModelConfig.hh"
#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/span.hh"
#include "simeng/version.hh"

namespace simeng {
namespace arch {
namespace riscv {

// RISC-V Tests
class RiscVArchitectureTest : public testing::Test {
 public:
  RiscVArchitectureTest()
      : config(ModelConfig(SIMENG_SOURCE_DIR "/configs/DEMO_RISCV.yaml")
                   .getConfigFile()),
        kernel(config["CPU-Info"]["Special-File-Dir-Path"].as<std::string>()) {
    arch = std::make_unique<Architecture>(kernel, config);
    kernel.createProcess(process);
  }

 protected:
  const std::string configPath = SIMENG_SOURCE_DIR "/configs/DEMO_RISCV.yaml";
  YAML::Node config;

  // addi	sp, ra, 2000
  std::array<uint8_t, 4> validInstrBytes = {0x13, 0x81, 0x00, 0x7d};
  std::array<uint8_t, 4> invalidInstrBytes = {0x7d, 0x00, 0x81, 0xbb};

  std::unique_ptr<Architecture> arch;
  kernel::Linux kernel;
  kernel::LinuxProcess process = kernel::LinuxProcess(
      span((char*)validInstrBytes.data(), validInstrBytes.size()), config);
};

TEST_F(RiscVArchitectureTest, predecode) {
  // Test that mis-aligned instruction address results in error
  MacroOp output;
  uint8_t result = arch->predecode(validInstrBytes.data(),
                                   validInstrBytes.size(), 0x7, output);
  EXPECT_EQ(result, 1);
  EXPECT_EQ(output[0]->getInstructionAddress(), 0x7);
  EXPECT_EQ(output[0]->exceptionEncountered(), true);

  // Test that an invalid instruction returns instruction with an exception
  output = MacroOp();
  result = arch->predecode(invalidInstrBytes.data(), invalidInstrBytes.size(),
                           0x8, output);
  EXPECT_EQ(result, 4);
  EXPECT_EQ(output[0]->getInstructionAddress(), 0x8);
  EXPECT_EQ(output[0]->exceptionEncountered(), true);

  // Test that an instruction can be properly decoded
  output = MacroOp();
  result = arch->predecode(validInstrBytes.data(), validInstrBytes.size(), 0x4,
                           output);
  EXPECT_EQ(result, 4);
  EXPECT_EQ(output[0]->getInstructionAddress(), 0x4);
  EXPECT_EQ(output[0]->exceptionEncountered(), false);
}

TEST_F(RiscVArchitectureTest, getRegisterFileStructures) {
  auto output = arch->getRegisterFileStructures();
  EXPECT_EQ(output[0].bytes, 8);
  EXPECT_EQ(output[0].quantity, 32);
  EXPECT_EQ(output[1].bytes, 8);
  EXPECT_EQ(output[1].quantity, 32);
  EXPECT_EQ(output[2].bytes, 8);
  EXPECT_EQ(output[2].quantity, arch->getNumSystemRegisters());
}

TEST_F(RiscVArchitectureTest, getSystemRegisterTag) {
  // Test incorrect system register will fail
  int32_t output = arch->getSystemRegisterTag(-1);
  EXPECT_EQ(output, -1);

  // Test for correct behaviour
  // TODO: Implement once system registers have been added
}

TEST_F(RiscVArchitectureTest, getNumSystemRegisters) {
  uint16_t output = arch->getNumSystemRegisters();
  EXPECT_EQ(output, 6);
}

TEST_F(RiscVArchitectureTest, handleException) {
  // Get Instruction
  MacroOp insn;
  uint8_t bytes = arch->predecode(invalidInstrBytes.data(),
                                  invalidInstrBytes.size(), 0x4, insn);
  EXPECT_EQ(bytes, 4);
  EXPECT_EQ(insn[0]->getInstructionAddress(), 0x4);
  EXPECT_EQ(insn[0]->exceptionEncountered(), true);

  // Get Core
  std::string executablePath = "";
  std::vector<std::string> executableArgs = {};
  std::unique_ptr<CoreInstance> coreInstance = std::make_unique<CoreInstance>(
      configPath, executablePath, executableArgs);
  const Core& core = *coreInstance->getCore();
  MemoryInterface& memInt = *coreInstance->getDataMemory();
  auto exceptionHandler = arch->handleException(insn[0], core, memInt);

  bool tickRes = exceptionHandler->tick();
  auto result = exceptionHandler->getResult();
  EXPECT_TRUE(tickRes);
  EXPECT_TRUE(result.fatal);
  // Instruction address for fatal exception is always 0.
  EXPECT_EQ(result.instructionAddress, 0x0);
}

TEST_F(RiscVArchitectureTest, getInitialState) {
  std::vector<Register> regs = {{RegisterType::GENERAL, 2}};
  std::vector<RegisterValue> regVals = {{kernel.getInitialStackPointer(), 8}};

  arch::ProcessStateChange changes = arch->getInitialState();
  EXPECT_EQ(changes.type, arch::ChangeType::REPLACEMENT);
  EXPECT_EQ(changes.modifiedRegisters, regs);
  EXPECT_EQ(changes.modifiedRegisterValues, regVals);
}

TEST_F(RiscVArchitectureTest, getMaxInstructionSize) {
  EXPECT_EQ(arch->getMaxInstructionSize(), 4);
}

TEST_F(RiscVArchitectureTest, updateSystemTimerRegisters) {
  // TODO: add tests once function has non-blank implementation.
}

TEST_F(RiscVArchitectureTest, getConfigPhysicalRegisterStructure) {
  std::vector<RegisterFileStructure> regStruct =
      arch->getConfigPhysicalRegisterStructure(config);
  // Values taken from DEMO_RISCV.yaml config file
  EXPECT_EQ(regStruct[0].bytes, 8);
  EXPECT_EQ(regStruct[0].quantity, 154);
  EXPECT_EQ(regStruct[1].bytes, 8);
  EXPECT_EQ(regStruct[1].quantity, 90);
  EXPECT_EQ(regStruct[2].bytes, 8);
  EXPECT_EQ(regStruct[2].quantity, arch->getNumSystemRegisters());
}

TEST_F(RiscVArchitectureTest, getConfigPhysicalRegisterQuantities) {
  std::vector<uint16_t> physQuants =
      arch->getConfigPhysicalRegisterQuantities(config);
  // Values taken from DEMO_RISCV.yaml config file
  EXPECT_EQ(physQuants[0], 154);
  EXPECT_EQ(physQuants[1], 90);
  EXPECT_EQ(physQuants[2], arch->getNumSystemRegisters());
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
